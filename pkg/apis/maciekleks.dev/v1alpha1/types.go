package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
type ClusterEgg struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterEggSpec `json:"spec,omitempty"`
	//Status ClusterEggStatus `json:"status,omitempty"`
}

/*
type ClusterEggStatus {

}*/

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterEggList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterEgg `json:"items,omitempty"`
}

type ClusterEggSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="IngressInterface is immutable"
	// +kubebuilder:validation:MaxLength=32
	IngressInterface string `json:"ingressInterface,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="EgressInterface is immutable"
	// +kubebuilder:validation:MaxLength=32
	EgressInterface string `json:"egressInterface,omitempty"`

	CommonNames []string `json:"commonNames,omitempty"`

	CIDRs []string `json:"cidrs,omitempty"`
}
