package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CommonClientRedirectUriSpec defines the desired state of CommonClientRedirectUri
type CommonClientRedirectUriSpec struct {

	// The redirect uri to add to the common Keycloak client
	RedirectUri string `json:"redirectUri"`

	// The client id of the common Keycloak client
	ClientId string `json:"clientId"`

	// The name of the secret to generate, if wanted
	SecretName string `json:"secretName,omitempty"`
}

// CommonClientRedirectUriStatus defines the observed state of CommonClientRedirectUri
type CommonClientRedirectUriStatus struct {
	// Current redirect uri in the common Keycloak client. If not set, the redirect uri is not in the client's redirect uris
	RedirectUri string `json:"redirectUri,omitempty"`

	// The client id of the common Keycloak client
	ClientId string `json:"clientId,omitempty"`

	// The name of the generated secret, if it exists
	SecretName string `json:"secretName,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CommonClientRedirectUri is the Schema for the commonclientredirecturis API
type CommonClientRedirectUri struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CommonClientRedirectUriSpec   `json:"spec,omitempty"`
	Status CommonClientRedirectUriStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CommonClientRedirectUriList contains a list of CommonClientRedirectUri
type CommonClientRedirectUriList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CommonClientRedirectUri `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CommonClientRedirectUri{}, &CommonClientRedirectUriList{})
}
