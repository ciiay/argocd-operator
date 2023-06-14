package argocd

import (
	"context"
	"fmt"
	"os"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	argoprojv1a1 "github.com/argoproj-labs/argocd-operator/api/v1alpha1"
	"github.com/argoproj-labs/argocd-operator/common"
	"github.com/argoproj-labs/argocd-operator/controllers/argoutil"
)

// newRole returns a new Role instance.
func newRole(name string, rules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) *v1.Role {
	return &v1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateResourceName(name, cr),
			Namespace: cr.Namespace,
			Labels:    argoutil.LabelsForCluster(cr),
		},
		Rules: rules,
	}
}

func newRoleForApplicationSourceNamespaces(namespace string, rules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) *v1.Role {
	return &v1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getRoleNameForApplicationSourceNamespaces(namespace, cr),
			Namespace: namespace,
			Labels:    argoutil.LabelsForCluster(cr),
		},
		Rules: rules,
	}
}

func generateResourceName(argoComponentName string, cr *argoprojv1a1.ArgoCD) string {
	return cr.Name + "-" + argoComponentName
}

// GenerateUniqueResourceName generates unique names for cluster scoped resources
func GenerateUniqueResourceName(argoComponentName string, cr *argoprojv1a1.ArgoCD) string {
	return cr.Name + "-" + cr.Namespace + "-" + argoComponentName
}

func newClusterRole(name string, rules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) *v1.ClusterRole {
	return &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:        GenerateUniqueResourceName(name, cr),
			Labels:      argoutil.LabelsForCluster(cr),
			Annotations: argoutil.AnnotationsForCluster(cr),
		},
		Rules: rules,
	}
}

// reconcileRoles will ensure that all ArgoCD Service Accounts are configured.
func (r *ReconcileArgoCD) reconcileRoles(ctx context.Context, cr *argoprojv1a1.ArgoCD) error {
	params := getPolicyRuleList(r.Client)

	for _, param := range params {
		if err := r.reconcileRole(param.name, param.policyRule, cr); err != nil {
			return err
		}
	}

	clusterParams := getPolicyRuleClusterRoleList()

	for _, clusterParam := range clusterParams {
		if _, err := r.reconcileClusterRole(clusterParam.name, clusterParam.policyRule, cr); err != nil {
			return err
		}
	}

	log.Info("reconciling roles for source namespaces")
	policyRuleForApplicationSourceNamespaces := policyRuleForServerApplicationSourceNamespaces()
	// reconcile roles is source namespaces for ArgoCD Server
	if err := r.reconcileRoleForApplicationSourceNamespaces(ctx, common.ArgoCDServerComponent, policyRuleForApplicationSourceNamespaces, cr); err != nil {
		return err
	}

	log.Info("performing cleanup for source namespaces")
	// remove resources for namespaces not part of SourceNamespaces
	if err := r.removeUnmanagedSourceNamespaceResources(ctx, cr); err != nil {
		return err
	}

	return nil
}

// reconcileRole, reconciles the policy rules for different ArgoCD components, for each namespace
// Managed by a single instance of ArgoCD.
func (r *ReconcileArgoCD) reconcileRole(name string, policyRules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) error {
	log.Info(fmt.Sprintf("Starting reconcileRole with name: %s", name))

	// Iterate through all managed namespaces
	for _, namespace := range r.ManagedNamespaces.Items {

		// Skip reconciliation for terminating namespace
		if namespace.DeletionTimestamp != nil {
			if _, ok := namespace.Labels[common.ArgoCDManagedByLabel]; ok {
				delete(namespace.Labels, common.ArgoCDManagedByLabel)
				_ = r.Client.Update(context.TODO(), &namespace)
			}
			continue
		}

		// Fetch the list of ArgoCD instances in the current namespace
		list := &argoprojv1a1.ArgoCDList{}
		listOption := &client.ListOptions{Namespace: namespace.Name}
		if err := r.Client.List(context.TODO(), list, listOption); err != nil {
			return err
		}

		// Skip creation of dex and redisHa roles for namespaces that no ArgoCD instance is deployed in
		if len(list.Items) < 1 && (name == common.ArgoCDDexServerComponent || name == common.ArgoCDRedisHAComponent) && cr.ObjectMeta.Namespace != namespace.Name {
			continue
		}

		// Create new role
		role := newRole(name, policyRules, cr)
		if err := applyReconcilerHook(cr, role, ""); err != nil {
			return err
		}
		role.Namespace = namespace.Name

		// Check if role exists
		existingRole := v1.Role{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, &existingRole)
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to reconcile the role for the service account associated with %s : %s", name, err)
		}

		// Determine if role exists and if it is a Dex role
		roleExists := err == nil
		isDex := name == common.ArgoCDDexServerComponent

		if roleExists {
			// If custom role is specified or Dex is disabled, delete existing role
			if getCustomRoleName(name) != "" || (isDex && !UseDex(cr)) {
				if err := r.Client.Delete(context.TODO(), &existingRole); err != nil {
					return err
				}
			} else if !reflect.DeepEqual(existingRole.Rules, role.Rules) {
				// Update the role if rules differ
				existingRole.Rules = role.Rules
				if err := r.Client.Update(context.TODO(), &existingRole); err != nil {
					return err
				}
			}
		} else if !isDex || UseDex(cr) {
			// If role doesn't exist, it's not a Dex role, or Dex is enabled, create new role
			if getCustomRoleName(name) != "" {
				continue
			}
			if cr.Namespace == role.Namespace {
				if err = controllerutil.SetControllerReference(cr, role, r.Scheme); err != nil {
					return fmt.Errorf("failed to set ArgoCD CR \"%s\" as owner for role \"%s\": %s", cr.Name, role.Name, err)
				}
			}
			if err := r.Client.Create(context.TODO(), role); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *ReconcileArgoCD) reconcileRoleForApplicationSourceNamespaces(ctx context.Context, name string, policyRules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) error {
	// create policy rules for each source namespace for ArgoCD Server
	for _, sourceNamespace := range cr.Spec.SourceNamespaces {
		namespace := &corev1.Namespace{}
		if err := r.Client.Get(ctx, types.NamespacedName{Name: sourceNamespace}, namespace); err != nil {
			return err
		}

		// do not reconcile roles for namespaces already containing managed-by label
		// as it already contains roles with permissions to manipulate application resources
		// reconciled during reconciliation of ManagedNamespaces
		if value, ok := namespace.Labels[common.ArgoCDManagedByLabel]; ok && value != "" {
			log.Info(fmt.Sprintf("Skipping reconciling resources for namespace %s as it is already managed-by namespace %s.", namespace.Name, value))
			// if managed-by-cluster-argocd label is also present, remove the namespace from the ManagedSourceNamespaces.
			if val, ok1 := namespace.Labels[common.ArgoCDManagedByClusterArgoCDLabel]; ok1 && val == cr.Namespace {
				r.Mutex.Lock()
				delete(r.ManagedSourceNamespaces, namespace.Name)
				r.Mutex.Unlock()
				if err := r.cleanupUnmanagedSourceNamespaceResources(ctx, cr, namespace.Name); err != nil {
					log.Error(err, fmt.Sprintf("error cleaning up resources for namespace %s", namespace.Name))
				}
			}
			continue
		}

		log.Info(fmt.Sprintf("Reconciling role for %s", namespace.Name))

		role := newRoleForApplicationSourceNamespaces(namespace.Name, policyRules, cr)
		if err := applyReconcilerHook(cr, role, ""); err != nil {
			return err
		}
		role.Namespace = namespace.Name

		existingRole := &v1.Role{}
		err := r.Client.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: namespace.Name}, existingRole)
		roleCreationNeeded := false
		if err != nil {
			if errors.IsNotFound(err) {
				roleCreationNeeded = true
			} else {
				return fmt.Errorf("failed to reconcile the role for the service account associated with %s : %s", name, err)
			}
		}

		r.Mutex.Lock()
		if _, ok := r.ManagedSourceNamespaces[sourceNamespace]; !ok {
			r.ManagedSourceNamespaces[sourceNamespace] = ""
		}
		r.Mutex.Unlock()

		if roleCreationNeeded || r.ManagedSourceNamespaces[sourceNamespace] == "" {
			if roleCreationNeeded {
				log.Info(fmt.Sprintf("creating role %s for Argo CD instance %s in namespace %s", role.Name, cr.Name, namespace.Name))
				if err := r.Client.Create(ctx, role); err != nil {
					return err
				}
			} else if !reflect.DeepEqual(existingRole.Rules, role.Rules) {
				existingRole.Rules = role.Rules
				if err := r.Client.Update(ctx, existingRole); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *ReconcileArgoCD) reconcileClusterRole(name string, policyRules []v1.PolicyRule, cr *argoprojv1a1.ArgoCD) (*v1.ClusterRole, error) {
	allowed := false
	if allowedNamespace(cr.Namespace, os.Getenv("ARGOCD_CLUSTER_CONFIG_NAMESPACES")) {
		allowed = true
	}
	clusterRole := newClusterRole(name, policyRules, cr)
	if err := applyReconcilerHook(cr, clusterRole, ""); err != nil {
		return nil, err
	}

	existingClusterRole := &v1.ClusterRole{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: clusterRole.Name}, existingClusterRole)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to reconcile the cluster role for the service account associated with %s : %s", name, err)
		}
		if !allowed {
			// Do Nothing
			return nil, nil
		}
		return clusterRole, r.Client.Create(context.TODO(), clusterRole)
	}

	if !allowed {
		return nil, r.Client.Delete(context.TODO(), existingClusterRole)
	}

	// if the Rules differ, update the Role
	if !reflect.DeepEqual(existingClusterRole.Rules, clusterRole.Rules) {
		existingClusterRole.Rules = clusterRole.Rules
		if err := r.Client.Update(context.TODO(), existingClusterRole); err != nil {
			return nil, err
		}
	}
	return existingClusterRole, nil
}

func deleteClusterRoles(c client.Client, clusterRoleList *v1.ClusterRoleList) error {
	for _, clusterRole := range clusterRoleList.Items {
		if err := c.Delete(context.TODO(), &clusterRole); err != nil {
			return fmt.Errorf("failed to delete ClusterRole %q during cleanup: %w", clusterRole.Name, err)
		}
	}
	return nil
}
