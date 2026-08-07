/*
Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
and other contributors as indicated by the @author tags.

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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// secretWithData builds a Secret carrying the given data for predicate testing.
func secretWithData(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-credential",
			Namespace: "default",
		},
		Data: data,
	}
}

func TestCredentialSecretPredicateDelete(t *testing.T) {
	pred := credentialSecretPredicate()

	if !pred.Delete(event.DeleteEvent{Object: secretWithData(nil)}) {
		t.Error("Delete() = false, want true: a deleted credential Secret must trigger reconciliation")
	}
}

func TestCredentialSecretPredicateCreateAndGeneric(t *testing.T) {
	pred := credentialSecretPredicate()

	if pred.Create(event.CreateEvent{Object: secretWithData(nil)}) {
		t.Error("Create() = true, want false: the operator's own writes must not enqueue work")
	}
	if pred.Generic(event.GenericEvent{Object: secretWithData(nil)}) {
		t.Error("Generic() = true, want false")
	}
}

func TestCredentialSecretPredicateUpdate(t *testing.T) {
	tests := []struct {
		name string
		old  map[string][]byte
		new  map[string][]byte
		want bool
	}{
		{
			name: "credential key removed",
			old:  map[string][]byte{"credential": []byte("jwt"), "format": []byte("jwt_vc_json")},
			new:  map[string][]byte{"format": []byte("jwt_vc_json")},
			want: true,
		},
		{
			name: "credential key emptied",
			old:  map[string][]byte{"credential": []byte("jwt")},
			new:  map[string][]byte{"credential": {}},
			want: true,
		},
		{
			name: "all data removed",
			old:  map[string][]byte{"credential": []byte("jwt")},
			new:  nil,
			want: true,
		},
		{
			name: "credential rotated in place",
			old:  map[string][]byte{"credential": []byte("old-jwt")},
			new:  map[string][]byte{"credential": []byte("new-jwt")},
			want: false,
		},
		{
			name: "rotation buffer added on renewal",
			old:  map[string][]byte{"credential": []byte("old-jwt")},
			new:  map[string][]byte{"credential": []byte("new-jwt"), "previousCredential": []byte("old-jwt")},
			want: false,
		},
		{
			name: "unrelated annotation-only change",
			old:  map[string][]byte{"credential": []byte("jwt")},
			new:  map[string][]byte{"credential": []byte("jwt")},
			want: false,
		},
		{
			name: "previously empty key stays empty",
			old:  map[string][]byte{"credential": []byte("jwt"), "previousCredential": {}},
			new:  map[string][]byte{"credential": []byte("jwt")},
			want: false,
		},
	}

	pred := credentialSecretPredicate()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pred.Update(event.UpdateEvent{
				ObjectOld: secretWithData(tt.old),
				ObjectNew: secretWithData(tt.new),
			})
			if got != tt.want {
				t.Errorf("Update() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredentialSecretPredicateUpdateNonSecret(t *testing.T) {
	pred := credentialSecretPredicate()

	// A non-Secret object must not panic and must not enqueue work.
	got := pred.Update(event.UpdateEvent{
		ObjectOld: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}},
		ObjectNew: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}},
	})
	if got {
		t.Error("Update() = true, want false for a non-Secret object")
	}
}
