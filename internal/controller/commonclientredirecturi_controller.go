package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"

	daplav1alpha1 "github.com/statisticsnorway/keycloak-redirecterator/api/v1alpha1"
)

// CommonClientRedirectUriReconciler reconciles a CommonClientRedirectUri object
type CommonClientRedirectUriReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Keycloak GocloakWrapper
}

var (
	finalizerName = fmt.Sprintf("%s/%s", daplav1alpha1.GroupVersion.Group, "commonclientredirecturi")
)

//+kubebuilder:rbac:groups=dapla.ssb.no,resources=commonclientredirecturis,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dapla.ssb.no,resources=commonclientredirecturis/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dapla.ssb.no,resources=commonclientredirecturis/finalizers,verbs=update

//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *CommonClientRedirectUriReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// Get the CommonClientRedirectUri resource with this namespace/name
	instance := &daplav1alpha1.CommonClientRedirectUri{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		// Error reading the object - requeue the request.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if instance is marked to be deleted, handle finalizer logic
	if result, err := r.handleFinalizer(ctx, instance); result != nil {
		return *result, err
	}

	if instance.Spec.ClientId != instance.Status.ClientId {
		// Update Keycloak client with new redirectUris, remove this resources' redirectUri
		redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Status.ClientId, nil)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := r.updateKeycloakClientRedirectUris(ctx, instance.Status.ClientId, redirectUris); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update Keycloak client with new redirectUris, add this resources' redirectUri
	redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Spec.ClientId, nil)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.updateKeycloakClientRedirectUris(ctx, instance.Spec.ClientId, redirectUris); err != nil {
		return ctrl.Result{}, err
	}

	// Get latest version of instance
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Update the status
	instance.Status.ClientId = instance.Spec.ClientId
	instance.Status.RedirectUri = instance.Spec.RedirectUri
	if err := r.Status().Update(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	// If the secret name has changed, delete the old secret
	if instance.Status.SecretName != instance.Spec.SecretName && instance.Status.SecretName != "" {
		secret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Name: instance.Status.SecretName, Namespace: instance.Namespace}, secret)
		if err != nil && errors.IsNotFound(err) {
			// If the secret does not exist, it has already been deleted
			instance.Status.SecretName = ""
			if err := r.Status().Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		} else if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				return ctrl.Result{}, err
			}
			instance.Status.SecretName = ""
			if err := r.Status().Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return ctrl.Result{}, err
		}
	}

	// If secretName is set, create the oauth2-proxy secret
	if instance.Spec.SecretName != "" {
		// Get Keycloak client
		kcClient, err := r.Keycloak.GetClient(ctx, instance.Spec.ClientId)
		if err != nil {
			return ctrl.Result{}, err
		}
		cookieSecret, err := generateCookieSecret()
		if err != nil {
			return ctrl.Result{}, err
		}
		secret := &corev1.Secret{
			ObjectMeta: ctrl.ObjectMeta{
				Name:        instance.Spec.SecretName,
				Namespace:   instance.Namespace,
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
			},
			StringData: map[string]string{
				"client-id":     instance.Spec.ClientId,
				"client-secret": *kcClient.Secret,
				"cookie-secret": cookieSecret,
			},
		}
		if err := ctrl.SetControllerReference(instance, secret, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}

		foundSecret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, foundSecret)
		if err != nil && errors.IsNotFound(err) {
			if err := r.Create(ctx, secret); err != nil {
				return ctrl.Result{}, err
			}
			// Update status
			instance.Status.SecretName = instance.Spec.SecretName
			if err := r.Status().Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		} else if err == nil {
			if foundSecret.StringData["client-id"] != secret.StringData["client-id"] {
				foundSecret.StringData = secret.StringData
				if err := r.Update(ctx, foundSecret); err != nil {
					return ctrl.Result{}, err
				}
			}
		} else {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CommonClientRedirectUriReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Index the clientId field for faster lookup
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &daplav1alpha1.CommonClientRedirectUri{}, "spec.clientId", func(rawObj client.Object) []string {
		instance := rawObj.(*daplav1alpha1.CommonClientRedirectUri)
		return []string{instance.Spec.ClientId}
	}); err != nil {
		return err
	}

	// Add index for secret owner reference
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Secret{}, ".metadata.controller", func(rawObj client.Object) []string {
		secret := rawObj.(*corev1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}
		if owner.APIVersion != daplav1alpha1.GroupVersion.String() || owner.Kind != "CommonClientRedirectUri" {
			return nil
		}
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&daplav1alpha1.CommonClientRedirectUri{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func generateCookieSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func isSameInstance(a, b *daplav1alpha1.CommonClientRedirectUri) bool {
	return a.Name == b.Name && a.Namespace == b.Namespace
}

func (r *CommonClientRedirectUriReconciler) getAllClientRedirectUrisFromSpecs(ctx context.Context, clientId string, exludedInstance *daplav1alpha1.CommonClientRedirectUri) ([]string, error) {
	instances := &daplav1alpha1.CommonClientRedirectUriList{}
	if err := r.List(ctx, instances, client.MatchingFields{"spec.clientId": clientId}); err != nil {
		return nil, err
	}

	redirectUris := make([]string, 0)
	for _, instance := range instances.Items {
		// Exclude instance if given
		if exludedInstance != nil && isSameInstance(&instance, exludedInstance) {
			continue
		}
		if !slices.Contains(redirectUris, instance.Spec.RedirectUri) {
			redirectUris = append(redirectUris, instance.Spec.RedirectUri)
		}
	}

	return redirectUris, nil
}

func (r *CommonClientRedirectUriReconciler) updateKeycloakClientRedirectUris(ctx context.Context, clientId string, redirectUris []string) error {
	// Get the client
	client, err := r.Keycloak.GetClient(ctx, clientId)
	if err != nil {
		return err
	}

	// Update the client
	client.RedirectURIs = &redirectUris
	if err := r.Keycloak.UpdateClient(ctx, *client); err != nil {
		return err
	}

	return nil
}

func (r *CommonClientRedirectUriReconciler) handleFinalizer(ctx context.Context, instance *daplav1alpha1.CommonClientRedirectUri) (*ctrl.Result, error) {
	if instance.GetDeletionTimestamp().IsZero() {
		// If resource does not have finalizer, add it
		if !controllerutil.ContainsFinalizer(instance, finalizerName) {
			controllerutil.AddFinalizer(instance, finalizerName)
			if err := r.Update(ctx, instance); err != nil {
				return &ctrl.Result{}, err
			}
		}
	} else {
		// Update Keycloak client with new redirectUris, remove this resources' redirectUri
		if controllerutil.ContainsFinalizer(instance, finalizerName) {
			// Get list of all CRs for this client, except this one
			redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Status.ClientId, instance)
			if err != nil {
				return &ctrl.Result{}, err
			}
			if err := r.updateKeycloakClientRedirectUris(ctx, instance.Status.ClientId, redirectUris); err != nil {
				return &ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(instance, finalizerName)
			if err := r.Update(ctx, instance); err != nil {
				return &ctrl.Result{}, err
			}
		}

		return &ctrl.Result{}, nil
	}

	return nil, nil
}
