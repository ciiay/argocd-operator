package argocd

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	argoprojv1alpha1 "github.com/argoproj-labs/argocd-operator/api/v1alpha1"
	"github.com/argoproj-labs/argocd-operator/common"
	"github.com/argoproj-labs/argocd-operator/controllers/argoutil"
)

func TestReconcileNotifications_CreateRoles(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	_, err := r.reconcileNotificationsRole(a)
	assert.NoError(t, err)

	testRole := &rbacv1.Role{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testRole))

	desiredPolicyRules := policyRuleForNotificationsController()

	assert.Equal(t, desiredPolicyRules, testRole.Rules)

	// Modify the rules of the existing role
	testRole.Rules = append(testRole.Rules, rbacv1.PolicyRule{
		Verbs:     []string{"get", "list"},
		APIGroups: []string{"", "apps", "extensions", "argoproj.io"},
		Resources: []string{"configmaps", "secrets"},
	})

	// Update the role with the modified rules
	assert.NoError(t, r.Client.Update(context.TODO(), testRole))

	// Reconcile again to correct the state
	_, err = r.reconcileNotificationsRole(a)
	assert.NoError(t, err)

	// Fetch the updated role
	updatedRole := &rbacv1.Role{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, updatedRole))

	// Assert that the rules have been updated back to match the desired state
	assert.Equal(t, desiredPolicyRules, updatedRole.Rules)
}

func TestReconcileNotifications_DeleteRoles(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	// Initially create the Role
	_, err := r.reconcileNotificationsRole(a)
	assert.NoError(t, err)

	testRole := &rbacv1.Role{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testRole))

	// Disable notifications, which should trigger deletion of the Role
	a.Spec.Notifications.Enabled = false
	err = r.deleteNotificationsRole(a)
	assert.NoError(t, err)

	// Check that the Role no longer exists
	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testRole)
	assert.True(t, errors.IsNotFound(err))
}

func TestReconcileNotifications_CreateServiceAccount(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	desiredSa, err := r.reconcileNotificationsServiceAccount(a)
	assert.NoError(t, err)

	testSa := &corev1.ServiceAccount{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testSa))

	assert.Equal(t, testSa.Name, desiredSa.Name)
}

func TestReconcileNotifications_DeleteServiceAccount(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = false
	})

	r := makeTestReconciler(t, a)

	sa := newServiceAccountWithName(common.ArgoCDNotificationsControllerComponent, a)

	// Create the ServiceAccount
	assert.NoError(t, r.Client.Create(context.TODO(), sa))

	// Ensure the ServiceAccount is created
	testSa := &corev1.ServiceAccount{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testSa))
	assert.Equal(t, testSa.Name, sa.Name)

	// Call the deleteNotificationsServiceAccount function
	err := r.deleteNotificationsServiceAccount(a, sa)
	assert.NoError(t, err)

	// Ensure the ServiceAccount is deleted
	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, testSa)
	assert.True(t, errors.IsNotFound(err))
}

func TestReconcileNotifications_CreateRoleBinding(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})
	r := makeTestReconciler(t, a)

	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role-name"}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa-name"}}

	err := r.reconcileNotificationsRoleBinding(a, role, sa)
	assert.NoError(t, err)

	roleBinding := &rbacv1.RoleBinding{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
			Namespace: a.Namespace,
		},
		roleBinding))

	assert.Equal(t, roleBinding.RoleRef.Name, role.Name)
	assert.Equal(t, roleBinding.Subjects[0].Name, sa.Name)
}

func TestReconcileNotifications_DeleteRoleBinding(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})
	r := makeTestReconciler(t, a)

	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role-name"}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa-name"}}

	// Assuming the role binding has been reconciled and exists
	err := r.reconcileNotificationsRoleBinding(a, role, sa)
	assert.NoError(t, err)

	roleBinding := &rbacv1.RoleBinding{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
			Namespace: a.Namespace,
		},
		roleBinding))

	// Confirm that the role binding exists
	assert.Equal(t, roleBinding.RoleRef.Name, role.Name)
	assert.Equal(t, roleBinding.Subjects[0].Name, sa.Name)

	// Now delete the role binding
	err = r.deleteNotificationsRoleBinding(a)
	assert.NoError(t, err)

	// Confirm the role binding has been deleted
	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, roleBinding)
	assert.True(t, errors.IsNotFound(err))
}

func TestReconcileNotifications_CreateDeployments(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	sa := corev1.ServiceAccount{}

	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	deployment := &appsv1.Deployment{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	// Ensure the created Deployment has the expected properties
	assert.Equal(t, deployment.Spec.Template.Spec.ServiceAccountName, sa.ObjectMeta.Name)

	want := []corev1.Container{{
		Command:         []string{"argocd-notifications", "--loglevel", "info"},
		Image:           argoutil.CombineImageTag(common.ArgoCDDefaultArgoImage, common.ArgoCDDefaultArgoVersion),
		ImagePullPolicy: corev1.PullAlways,
		Name:            "argocd-notifications-controller",
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{
					"ALL",
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "tls-certs",
				MountPath: "/app/config/tls",
			},
			{
				Name:      "argocd-repo-server-tls",
				MountPath: "/app/config/reposerver/tls",
			},
		},
		Resources:  corev1.ResourceRequirements{},
		WorkingDir: "/app",
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.IntOrString{
						IntVal: int32(9001),
					},
				},
			},
		},
	}}

	if diff := cmp.Diff(want, deployment.Spec.Template.Spec.Containers); diff != "" {
		t.Fatalf("failed to reconcile notifications-controller deployment containers:\n%s", diff)
	}

	volumes := []corev1.Volume{
		{
			Name: "tls-certs",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "argocd-tls-certs-cm",
					},
				},
			},
		},
		{
			Name: "argocd-repo-server-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "argocd-repo-server-tls",
					Optional:   boolPtr(true),
				},
			},
		},
	}

	if diff := cmp.Diff(volumes, deployment.Spec.Template.Spec.Volumes); diff != "" {
		t.Fatalf("failed to reconcile notifications-controller deployment volumes:\n%s", diff)
	}

	expectedSelector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			common.ArgoCDKeyName: deployment.Name,
		},
	}

	if diff := cmp.Diff(expectedSelector, deployment.Spec.Selector); diff != "" {
		t.Fatalf("failed to reconcile notifications-controller label selector:\n%s", diff)
	}
}

func TestReconcileNotifications_DeleteDeployments(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})
	r := makeTestReconciler(t, a)
	sa := corev1.ServiceAccount{}
	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	deployment := &appsv1.Deployment{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	// Ensure the created Deployment has the expected properties
	assert.Equal(t, deployment.Spec.Template.Spec.ServiceAccountName, sa.ObjectMeta.Name)

	// Ensure the deployment is deleted
	a.Spec.Notifications.Enabled = false
	err := r.deleteNotificationsDeployment(a)
	assert.NoError(t, err)

	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      generateResourceName(common.ArgoCDNotificationsControllerComponent, a),
		Namespace: a.Namespace,
	}, deployment)
	assert.True(t, errors.IsNotFound(err))
}

func TestReconcileNotifications_CreateSecret(t *testing.T) {
	logf.SetLogger(ZapLogger(true))

	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	err := r.reconcileNotificationsSecret(a)
	assert.NoError(t, err)

	testSecret := &corev1.Secret{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "argocd-notifications-secret",
		Namespace: a.Namespace,
	}, testSecret))
}

func TestDeleteNotifications_DeleteSecret(t *testing.T) {
	logf.SetLogger(ZapLogger(true))

	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = false
	})

	r := makeTestReconciler(t, a)

	err := r.deleteNotificationsSecret(a)
	assert.NoError(t, err)

	secret := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "argocd-notifications-secret",
		Namespace: a.Namespace,
	}, secret)
	assertNotFound(t, err)
}

func TestReconcileNotifications_CreateConfigMap(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
	})

	r := makeTestReconciler(t, a)

	err := r.reconcileNotificationsConfigMap(a)
	assert.NoError(t, err)

	testCm := &corev1.ConfigMap{}
	assert.NoError(t, r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "argocd-notifications-cm",
		Namespace: a.Namespace,
	}, testCm))

	assert.True(t, len(testCm.Data) > 0)
}

func TestReconcileNotifications_DeleteConfigMap(t *testing.T) {
	logf.SetLogger(ZapLogger(true))
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = false
	})

	r := makeTestReconciler(t, a)

	// Create the existing ConfigMap
	existingCm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-notifications-cm",
			Namespace: a.Namespace,
		},
	}
	assert.NoError(t, r.Client.Create(context.TODO(), existingCm))

	err := r.deleteNotificationsConfigMap(a)
	assert.NoError(t, err)

	// Check if the ConfigMap was deleted
	cm := &corev1.ConfigMap{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      "argocd-notifications-cm",
		Namespace: a.Namespace,
	}, cm)
	assert.True(t, errors.IsNotFound(err))
}

func TestReconcileNotifications_testEnvVars(t *testing.T) {

	envMap := []corev1.EnvVar{
		{
			Name:  "foo",
			Value: "bar",
		},
	}
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
		a.Spec.Notifications.Env = envMap
	})

	r := makeTestReconciler(t, a)

	sa := corev1.ServiceAccount{}
	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	deployment := &appsv1.Deployment{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	if diff := cmp.Diff(envMap, deployment.Spec.Template.Spec.Containers[0].Env); diff != "" {
		t.Fatalf("failed to reconcile notifications-controller deployment env:\n%s", diff)
	}

	// Verify any manual updates to the env vars should be overridden by the operator.
	unwantedEnv := []corev1.EnvVar{
		{
			Name:  "foo",
			Value: "bar",
		},
		{
			Name:  "ping",
			Value: "pong",
		},
	}

	deployment.Spec.Template.Spec.Containers[0].Env = unwantedEnv
	assert.NoError(t, r.Client.Update(context.TODO(), deployment))

	// Reconcile back
	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	// Get the updated deployment
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	if diff := cmp.Diff(envMap, deployment.Spec.Template.Spec.Containers[0].Env); diff != "" {
		t.Fatalf("operator failed to override the manual changes to notification controller:\n%s", diff)
	}
}

func TestReconcileNotifications_testLogLevel(t *testing.T) {

	testLogLevel := "debug"
	a := makeTestArgoCD(func(a *argoprojv1alpha1.ArgoCD) {
		a.Spec.Notifications.Enabled = true
		a.Spec.Notifications.LogLevel = testLogLevel
	})

	r := makeTestReconciler(t, a)

	sa := corev1.ServiceAccount{}
	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	deployment := &appsv1.Deployment{}
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	expectedCMD := []string{
		"argocd-notifications",
		"--loglevel",
		"debug",
	}

	if diff := cmp.Diff(expectedCMD, deployment.Spec.Template.Spec.Containers[0].Command); diff != "" {
		t.Fatalf("failed to reconcile notifications-controller deployment logLevel:\n%s", diff)
	}

	// Verify any manual updates to the logLevel should be overridden by the operator.
	unwantedCommand := []string{
		"argocd-notifications",
		"--logLevel",
		"info",
	}

	deployment.Spec.Template.Spec.Containers[0].Command = unwantedCommand
	assert.NoError(t, r.Client.Update(context.TODO(), deployment))

	// Reconcile back
	assert.NoError(t, r.reconcileNotificationsDeployment(a, &sa))

	// Get the updated deployment
	assert.NoError(t, r.Client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      a.Name + "-notifications-controller",
			Namespace: a.Namespace,
		},
		deployment))

	if diff := cmp.Diff(expectedCMD, deployment.Spec.Template.Spec.Containers[0].Command); diff != "" {
		t.Fatalf("operator failed to override the manual changes to notification controller:\n%s", diff)
	}
}
