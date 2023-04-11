package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterEgg struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterEggSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterEggList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ClusterEgg
}

type ClusterEggSpec struct {
	Name string `json:"name,omitempty"`

	IngressInterface string   `json:"ingressInterface,omitempty"`
	EgressInterface  string   `json:"egressInterface,omitempty"`
	CommonNames      []string `json:"commonNames,omitempty"`
	CIDRs            []string `json:"cidrs,omitempty"`
}
