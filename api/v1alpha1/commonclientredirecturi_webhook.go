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

package v1alpha1

import (
	"os"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// log is for logging in this package.
var commonclientredirecturilog = logf.Log.WithName("commonclientredirecturi-resource")

func (r *CommonClientRedirectUri) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-dapla-ssb-no-v1alpha1-commonclientredirecturi,mutating=false,failurePolicy=fail,sideEffects=None,groups=dapla.ssb.no,resources=commonclientredirecturis,verbs=create;update,versions=v1alpha1,name=vcommonclientredirecturi.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &CommonClientRedirectUri{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *CommonClientRedirectUri) ValidateCreate() (admission.Warnings, error) {
	commonclientredirecturilog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil, r.validateSpec()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *CommonClientRedirectUri) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	commonclientredirecturilog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil, r.validateSpec()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *CommonClientRedirectUri) ValidateDelete() (admission.Warnings, error) {
	commonclientredirecturilog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

func (r *CommonClientRedirectUri) validateSpec() error {
	var allErrs field.ErrorList
	if r.Spec.RedirectUri == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "redirectUri"), "redirectUri cannot be empty"))
	}
	if r.Spec.ClientId == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "clientId"), "clientId cannot be empty"))
	}
	if !isInWhitelist(r.Spec.ClientId) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "clientId"), r.Spec.ClientId, "clientId is not in whitelist"))
	}

	if ok, err := satisfiesUriRegex(r.Spec.RedirectUri); err != nil {
		return err
	} else if !ok {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "redirectUri"), r.Spec.RedirectUri, "redirectUri does not satisfy validation regex"))
	}

	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		schema.GroupKind{Group: GroupVersion.Group, Kind: "CommonClientRedirectUri"},
		r.Name, allErrs)
}

func isInWhitelist(clientId string) bool {
	if whitelist := os.Getenv("KEYCLOAK_CLIENT_ID_WHITELIST"); whitelist != "" {
		return slices.Contains(strings.Split(whitelist, ","), clientId)
	}

	// If no whitelist is set, all clients are allowed
	return true
}

func satisfiesUriRegex(redirectUri string) (bool, error) {
	pattern := os.Getenv("KEYCLOAK_REDIRECT_URI_REGEX")
	if pattern == "" {
		return true, nil
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}

	return regex.MatchString(redirectUri), nil
}
