package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
type ClusterEgg struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:XValidation:rule="(self.programType == 'tc' && has(self.egress.interfaceName)) || (self.programType == 'cgroup' && !has(self.egress.interfaceName))",message="Egress interfaceName works only with tc program"
	// +kubebuilder:validation:XValidation:rule="(self.programType == 'tc' && has(self.ingress.interfaceName)) || (self.programType =='cgroup' && !has(self.ingress.interfaceName))",message="Ingress interfaceName works only with tc program"
	// +kubebuilder:validation:XValidation:rule="self.programType == 'cgroup' && has(self.egress.podSelector)",message="Cgroup program requires podSelector"
	Spec   ClusterEggSpec   `json:"spec,omitempty"`
	Status ClusterEggStatus `json:"status,omitempty"`
}

type ClusterEggStatus struct {
	Ready bool `json:"ready,omitempty"`
	//Blocked uint64 `json:"blocked,omitempty"

}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterEggList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterEgg `json:"items,omitempty"`
}

type ClusterEggSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tc;cgroup
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="attachType is immutable"
	// +kubebuilder:default=cgroup
	ProgramType string      `json:"programType,omitempty"`
	Egress      EgressSpec  `json:"egress,omitempty"`
	Ingress     IngressSpec `json:"ingress,omitempty"`
}

type IngressSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="interfaceName is immutable"
	// +kubebuilder:validation:MaxLength=32
	InterfaceName string `json:"interfaceName,omitempty"`
}

type EgressSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="interfaceName is immutable"
	// +kubebuilder:validation:MaxLength=32
	InterfaceName string `json:"interfaceName,omitempty"`

	CommonNames []string `json:"commonNames,omitempty"`

	CIDRs []string `json:"cidrs,omitempty"`

	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="shaping is immutable in this version"
	// +optional
	Shaping *ShapingSpec `json:"shaping,omitempty"`

	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
}

type ShapingSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^\d+[k|m]bit$`
	Rate string `json:"rate,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^\d+[k|m]bit$`
	Ceil string `json:"ceil,omitempty"`
}
