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
		// Clean up exernal resources and remove finalizer
		if controllerutil.ContainsFinalizer(instance, finalizerName) {
			if err := r.cleanUpExternalResources(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(instance, finalizerName)
			if err := r.Update(ctx, instance); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// If the client id or redirect uri has changed, remove the redirect uri from the status client
	if instance.Status.ClientId != instance.Spec.ClientId || instance.Status.RedirectUri != instance.Spec.RedirectUri {
		if err := r.cleanUpExternalResources(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}

		// Get instance again to get the latest version
		if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}

		// Update the status
		instance.Status = daplav1alpha1.CommonClientRedirectUriStatus{}
		if err := r.Status().Update(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
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

	// Get the Keycloak client
	kcClient, err := r.Keycloak.getClientFromId(ctx, instance.Spec.ClientId)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Add the redirect uri to the client
	*kcClient.RedirectURIs = append(*kcClient.RedirectURIs, instance.Spec.RedirectUri)

	// Update the client
	if err := r.Keycloak.UpdateClient(ctx, r.Keycloak.Token.AccessToken, r.Keycloak.Realm, *kcClient); err != nil {
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

	// If secretName is set, create the oauth2-proxy secret
	if instance.Spec.SecretName != instance.Status.SecretName && instance.Spec.SecretName != "" {
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
			foundSecret.StringData = secret.StringData
			if err := r.Update(ctx, foundSecret); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CommonClientRedirectUriReconciler) SetupWithManager(mgr ctrl.Manager) error {
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
