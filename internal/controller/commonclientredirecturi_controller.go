/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"

	"github.com/Nerzal/gocloak/v13"
	daplav1alpha1 "github.com/statisticsnorway/dapla-operator/api/v1alpha1"
)

type GocloakWrapper struct {
	gocloak.GoCloak
	Token        *gocloak.JWT
	ClientId     string
	ClientSecret string
	Realm        string
	TokenExpiry  int
}

// CommonClientRedirectUriReconciler reconciles a CommonClientRedirectUri object
type CommonClientRedirectUriReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Keycloak *GocloakWrapper
}

func (k *GocloakWrapper) ensureToken(ctx context.Context) error {
	if k.Token == nil {
		token, err := k.LoginClient(ctx, k.ClientId, k.ClientSecret, k.Realm)
		if err != nil {
			return err
		}
		k.Token = token

		retrospect, err := k.RetrospectToken(ctx, token.AccessToken, k.ClientId, k.ClientSecret, k.Realm)
		if err != nil {
			return err
		}
		if !*retrospect.Active {
			return fmt.Errorf("token is not active")
		}
		k.TokenExpiry = *retrospect.Exp
		return nil
	}

	// If token is about to expire, get a new one
	if time.Now().UTC().Unix()+600 > int64(k.TokenExpiry) {
		k.Token = nil
		return k.ensureToken(ctx)
	}

	return nil
}

func (k *GocloakWrapper) getClientFromId(ctx context.Context, clientId string) (*gocloak.Client, error) {
	// Ensure we are authenticated with Keycloak
	if err := k.ensureToken(ctx); err != nil {
		return nil, err
	}

	// Get all clients in realm matching filter (should only be one)
	// Gocloak has no way of getting a single client by id (only by internal id)
	clients, err := k.GetClients(ctx, k.Token.AccessToken, k.Realm, gocloak.GetClientsParams{
		ClientID: &clientId,
	})
	if err != nil {
		return nil, err
	}

	// Clients should only contain one client, which is the one we want
	for _, client := range clients {
		return client, nil
	}

	// If clients is empty, the client does not exist
	return nil, fmt.Errorf("client with id %s not found", clientId)
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

	// Check if the resource is marked to be deleted
	if instance.GetDeletionTimestamp().IsZero() {
		// If resource does not have finalizer, add it
		if !controllerutil.ContainsFinalizer(instance, finalizerName) {
			controllerutil.AddFinalizer(instance, finalizerName)
			if err := r.Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// Update Keycloak client with new redirectUris, remove this resources' redirectUri
		if controllerutil.ContainsFinalizer(instance, finalizerName) {
			// Get clientId from status as it is no longer in spec
			redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Status.ClientId)
			if err != nil {
				return ctrl.Result{}, err
			}
			if err := r.updateKeycloakClientRedirectUris(ctx, instance.Status.ClientId, redirectUris); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(instance, finalizerName)
			if err := r.Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	if instance.Spec.ClientId != instance.Status.ClientId {
		// Update Keycloak client with new redirectUris, remove this resources' redirectUri
		redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Status.ClientId)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := r.updateKeycloakClientRedirectUris(ctx, instance.Status.ClientId, redirectUris); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update Keycloak client with new redirectUris, add this resources' redirectUri
	redirectUris, err := r.getAllClientRedirectUrisFromSpecs(ctx, instance.Spec.ClientId)
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
		kcClient, err := r.Keycloak.getClientFromId(ctx, instance.Spec.ClientId)
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&daplav1alpha1.CommonClientRedirectUri{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *CommonClientRedirectUriReconciler) cleanUpExternalResources(ctx context.Context, instance *daplav1alpha1.CommonClientRedirectUri) error {

	clientId := instance.Status.ClientId
	redirectUri := instance.Status.RedirectUri

	// If this is the case, chances are that the resource has been deleted already
	if clientId == "" || redirectUri == "" {
		return nil
	}

	// Ensure we are authenticated with Keycloak
	if err := r.Keycloak.ensureToken(ctx); err != nil {
		return err
	}

	// Get the client
	client, err := r.Keycloak.getClientFromId(ctx, clientId)
	if err != nil {
		return err
	}

	// Remove the redirect uri from the client
	for i, uri := range *client.RedirectURIs {
		if uri == redirectUri {
			*client.RedirectURIs = append((*client.RedirectURIs)[:i], (*client.RedirectURIs)[i+1:]...)
			break
		}
	}

	// Update the client
	if err := r.Keycloak.UpdateClient(ctx, r.Keycloak.Token.AccessToken, r.Keycloak.Realm, *client); err != nil {
		return err
	}

	return nil
}

func generateCookieSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (r *CommonClientRedirectUriReconciler) getAllClientRedirectUrisFromSpecs(ctx context.Context, clientId string) ([]string, error) {
	instances := &daplav1alpha1.CommonClientRedirectUriList{}
	if err := r.List(ctx, instances, client.MatchingFields{"spec.clientId": clientId}); err != nil {
		return nil, err
	}

	redirectUris := make([]string, 0)
	for _, instance := range instances.Items {
		if !slices.Contains(redirectUris, instance.Spec.RedirectUri) {
			redirectUris = append(redirectUris, instance.Spec.RedirectUri)
		}
	}

	return redirectUris, nil
}

func (r *CommonClientRedirectUriReconciler) updateKeycloakClientRedirectUris(ctx context.Context, clientId string, redirectUris []string) error {
	// Ensure we are authenticated with Keycloak
	if err := r.Keycloak.ensureToken(ctx); err != nil {
		return err
	}

	// Get the client
	client, err := r.Keycloak.getClientFromId(ctx, clientId)
	if err != nil {
		return err
	}

	// Update the client
	client.RedirectURIs = &redirectUris
	if err := r.Keycloak.UpdateClient(ctx, r.Keycloak.Token.AccessToken, r.Keycloak.Realm, *client); err != nil {
		return err
	}

	return nil
}
