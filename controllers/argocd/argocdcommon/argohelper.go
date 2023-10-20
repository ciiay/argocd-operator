package argocdcommon

import (
	"context"
	"fmt"
	"os"
	"strings"

	argoproj "github.com/argoproj-labs/argocd-operator/api/v1beta1"
	"github.com/argoproj-labs/argocd-operator/common"
	"github.com/argoproj-labs/argocd-operator/pkg/util"
	"github.com/argoproj-labs/argocd-operator/pkg/workloads"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cntrlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

func GetArgoContainerImage(cr *argoproj.ArgoCD) string {
	defaultTag, defaultImg := false, false
	img := cr.Spec.Image
	if img == "" {
		img = common.ArgoCDDefaultArgoImage
		defaultImg = true
	}

	tag := cr.Spec.Version
	if tag == "" {
		tag = common.ArgoCDDefaultArgoVersion
		defaultTag = true
	}
	if e := os.Getenv(common.ArgoCDImageEnvVar); e != "" && (defaultTag && defaultImg) {
		return e
	}

	return util.CombineImageTag(img, tag)
}

// getArgoCmpServerInitCommand will return the command for the ArgoCD CMP Server init container
func GetArgoCmpServerInitCommand() []string {
	cmd := make([]string, 0)
	cmd = append(cmd, "cp")
	cmd = append(cmd, "-n")
	cmd = append(cmd, "/usr/local/bin/argocd")
	cmd = append(cmd, "/var/run/argocd/argocd-cmp-server")
	return cmd
}

// isOwnerOfInterest returns true if the given owner is one of the Argo CD services that
// may have been made the owner of the tls secret created by the OpenShift service CA, used
// to secure communication amongst the Argo CD components.
func IsOwnerOfInterest(owner metav1.OwnerReference) bool {
	if owner.Kind != "Service" {
		return false
	}
	if strings.HasSuffix(owner.Name, "-repo-server") {
		return true
	}
	if strings.HasSuffix(owner.Name, "-redis") {
		return true
	}
	return false
}

// TriggerRollout will trigger a rollout of a Kubernetes resource specified as
// obj. It currently supports Deployment and StatefulSet resources.
func TriggerRollout(client cntrlClient.Client, name, namespace, resType string, opt func(name string, namespace string)) error {
	switch resType {
	case common.DeploymentKind:
		return workloads.TriggerDeploymentRollout(client, name, namespace, opt)
	case common.StatefulSetKind:
		return workloads.TriggerStatefulSetRollout(client, name, namespace, opt)
	default:
		return fmt.Errorf("resource of unknown type %T, cannot trigger rollout", resType)
	}
}

func ShouldUseTLS(client cntrlClient.Client, instanceNamespace string) (bool, error) {
	tlsSecretName := types.NamespacedName{Namespace: instanceNamespace, Name: common.ArgoCDRedisServerTLSSecretName}
	var tlsSecretObj corev1.Secret
	if err := client.Get(context.TODO(), tlsSecretName, &tlsSecretObj); err != nil {
		if !errors.IsNotFound(err) {
			return false, err
		}
		return false, nil
	}

	secretOwnerRefs := tlsSecretObj.GetOwnerReferences()
	if len(secretOwnerRefs) > 0 {
		// OpenShift service CA makes the owner reference for the TLS secret to the
		// service, which in turn is owned by the controller. This method performs
		// a lookup of the controller through the intermediate owning service.
		for _, secretOwner := range secretOwnerRefs {
			if IsOwnerOfInterest(secretOwner) {
				key := cntrlClient.ObjectKey{Name: secretOwner.Name, Namespace: tlsSecretObj.GetNamespace()}
				svc := &corev1.Service{}
				// Get the owning object of the secret
				if err := client.Get(context.TODO(), key, svc); err != nil {
					return false, err
				}

				// If there's an object of kind ArgoCD in the owner's list,
				// this will be our reconciled object.
				serviceOwnerRefs := svc.GetOwnerReferences()
				for _, serviceOwner := range serviceOwnerRefs {
					if serviceOwner.Kind == "ArgoCD" {
						return true, nil
					}
				}
			}
		}
	} else {
		// For secrets without owner (i.e. manually created), we apply some
		// heuristics. This may not be as accurate (e.g. if the user made a
		// typo in the resource's name), but should be good enough for now.
		if _, ok := tlsSecretObj.Annotations[common.ArgoCDArgoprojKeyName]; ok {
			return true, nil
		}
	}
	return false, nil
}

// getRedisServerAddress will return the Redis service address for the given ArgoCD.
func GetRedisServerAddress(cr *argoproj.ArgoCD) string {
	if cr.Spec.HA.Enabled {
		return GetRedisHAProxyAddress(cr.Namespace)
	}
	return util.FqdnServiceRef(common.ArgoCDDefaultRedisSuffix, cr.Namespace, common.ArgoCDDefaultRedisPort)
}

// getRedisHAProxyAddress will return the Redis HA Proxy service address for the given ArgoCD.
func GetRedisHAProxyAddress(namespace string) string {
	return util.FqdnServiceRef(common.RedisHAProxyServiceName, namespace, common.ArgoCDDefaultRedisPort)
}
