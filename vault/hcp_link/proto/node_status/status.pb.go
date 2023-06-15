// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.1
// 	protoc        v3.21.12
// source: vault/hcp_link/proto/node_status/status.proto

package node_status

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LogLevel int32

const (
	LogLevel_NO_LEVEL LogLevel = 0
	LogLevel_TRACE    LogLevel = 1
	LogLevel_DEBUG    LogLevel = 2
	LogLevel_INFO     LogLevel = 3
	LogLevel_WARN     LogLevel = 4
	LogLevel_ERROR    LogLevel = 5
)

// Enum value maps for LogLevel.
var (
	LogLevel_name = map[int32]string{
		0: "NO_LEVEL",
		1: "TRACE",
		2: "DEBUG",
		3: "INFO",
		4: "WARN",
		5: "ERROR",
	}
	LogLevel_value = map[string]int32{
		"NO_LEVEL": 0,
		"TRACE":    1,
		"DEBUG":    2,
		"INFO":     3,
		"WARN":     4,
		"ERROR":    5,
	}
)

func (x LogLevel) Enum() *LogLevel {
	p := new(LogLevel)
	*p = x
	return p
}

func (x LogLevel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogLevel) Descriptor() protoreflect.EnumDescriptor {
	return file_vault_hcp_link_proto_node_status_status_proto_enumTypes[0].Descriptor()
}

func (LogLevel) Type() protoreflect.EnumType {
	return &file_vault_hcp_link_proto_node_status_status_proto_enumTypes[0]
}

func (x LogLevel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogLevel.Descriptor instead.
func (LogLevel) EnumDescriptor() ([]byte, []int) {
	return file_vault_hcp_link_proto_node_status_status_proto_rawDescGZIP(), []int{0}
}

type RaftStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsVoter bool `protobuf:"varint,1,opt,name=IsVoter,proto3" json:"IsVoter,omitempty"`
}

func (x *RaftStatus) Reset() {
	*x = RaftStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_vault_hcp_link_proto_node_status_status_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RaftStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RaftStatus) ProtoMessage() {}

func (x *RaftStatus) ProtoReflect() protoreflect.Message {
	mi := &file_vault_hcp_link_proto_node_status_status_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RaftStatus.ProtoReflect.Descriptor instead.
func (*RaftStatus) Descriptor() ([]byte, []int) {
	return file_vault_hcp_link_proto_node_status_status_proto_rawDescGZIP(), []int{0}
}

func (x *RaftStatus) GetIsVoter() bool {
	if x != nil {
		return x.IsVoter
	}
	return false
}

type LinkedClusterNodeStatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type                   string                 `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	Initialized            bool                   `protobuf:"varint,2,opt,name=Initialized,proto3" json:"Initialized,omitempty"`
	Sealed                 bool                   `protobuf:"varint,3,opt,name=Sealed,proto3" json:"Sealed,omitempty"`
	T                      int64                  `protobuf:"varint,4,opt,name=T,proto3" json:"T,omitempty"`
	N                      int64                  `protobuf:"varint,5,opt,name=N,proto3" json:"N,omitempty"`
	Progress               int64                  `protobuf:"varint,6,opt,name=Progress,proto3" json:"Progress,omitempty"`
	Nonce                  string                 `protobuf:"bytes,7,opt,name=Nonce,proto3" json:"Nonce,omitempty"`
	Version                string                 `protobuf:"bytes,8,opt,name=Version,proto3" json:"Version,omitempty"`
	BuildDate              string                 `protobuf:"bytes,9,opt,name=BuildDate,proto3" json:"BuildDate,omitempty"`
	Migration              bool                   `protobuf:"varint,10,opt,name=Migration,proto3" json:"Migration,omitempty"`
	ClusterName            string                 `protobuf:"bytes,11,opt,name=ClusterName,proto3" json:"ClusterName,omitempty"`
	ClusterID              string                 `protobuf:"bytes,12,opt,name=ClusterID,proto3" json:"ClusterID,omitempty"`
	RecoverySeal           bool                   `protobuf:"varint,13,opt,name=RecoverySeal,proto3" json:"RecoverySeal,omitempty"`
	StorageType            string                 `protobuf:"bytes,14,opt,name=StorageType,proto3" json:"StorageType,omitempty"`
	ReplicationState       []string               `protobuf:"bytes,15,rep,name=ReplicationState,proto3" json:"ReplicationState,omitempty"`
	Hostname               string                 `protobuf:"bytes,16,opt,name=Hostname,proto3" json:"Hostname,omitempty"`
	ListenerAddresses      []string               `protobuf:"bytes,17,rep,name=ListenerAddresses,proto3" json:"ListenerAddresses,omitempty"`
	OperatingSystem        string                 `protobuf:"bytes,18,opt,name=OperatingSystem,proto3" json:"OperatingSystem,omitempty"`
	OperatingSystemVersion string                 `protobuf:"bytes,19,opt,name=OperatingSystemVersion,proto3" json:"OperatingSystemVersion,omitempty"`
	LogLevel               LogLevel               `protobuf:"varint,20,opt,name=LogLevel,proto3,enum=hashicorp.vault.hcp_link.node_status.LogLevel" json:"LogLevel,omitempty"`
	ActiveTime             *timestamppb.Timestamp `protobuf:"bytes,21,opt,name=ActiveTime,proto3" json:"ActiveTime,omitempty"`
	RaftStatus             *RaftStatus            `protobuf:"bytes,22,opt,name=RaftStatus,proto3" json:"RaftStatus,omitempty"`
}

func (x *LinkedClusterNodeStatusResponse) Reset() {
	*x = LinkedClusterNodeStatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_vault_hcp_link_proto_node_status_status_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LinkedClusterNodeStatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LinkedClusterNodeStatusResponse) ProtoMessage() {}

func (x *LinkedClusterNodeStatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_vault_hcp_link_proto_node_status_status_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LinkedClusterNodeStatusResponse.ProtoReflect.Descriptor instead.
func (*LinkedClusterNodeStatusResponse) Descriptor() ([]byte, []int) {
	return file_vault_hcp_link_proto_node_status_status_proto_rawDescGZIP(), []int{1}
}

func (x *LinkedClusterNodeStatusResponse) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetInitialized() bool {
	if x != nil {
		return x.Initialized
	}
	return false
}

func (x *LinkedClusterNodeStatusResponse) GetSealed() bool {
	if x != nil {
		return x.Sealed
	}
	return false
}

func (x *LinkedClusterNodeStatusResponse) GetT() int64 {
	if x != nil {
		return x.T
	}
	return 0
}

func (x *LinkedClusterNodeStatusResponse) GetN() int64 {
	if x != nil {
		return x.N
	}
	return 0
}

func (x *LinkedClusterNodeStatusResponse) GetProgress() int64 {
	if x != nil {
		return x.Progress
	}
	return 0
}

func (x *LinkedClusterNodeStatusResponse) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetBuildDate() string {
	if x != nil {
		return x.BuildDate
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetMigration() bool {
	if x != nil {
		return x.Migration
	}
	return false
}

func (x *LinkedClusterNodeStatusResponse) GetClusterName() string {
	if x != nil {
		return x.ClusterName
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetClusterID() string {
	if x != nil {
		return x.ClusterID
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetRecoverySeal() bool {
	if x != nil {
		return x.RecoverySeal
	}
	return false
}

func (x *LinkedClusterNodeStatusResponse) GetStorageType() string {
	if x != nil {
		return x.StorageType
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetReplicationState() []string {
	if x != nil {
		return x.ReplicationState
	}
	return nil
}

func (x *LinkedClusterNodeStatusResponse) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetListenerAddresses() []string {
	if x != nil {
		return x.ListenerAddresses
	}
	return nil
}

func (x *LinkedClusterNodeStatusResponse) GetOperatingSystem() string {
	if x != nil {
		return x.OperatingSystem
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetOperatingSystemVersion() string {
	if x != nil {
		return x.OperatingSystemVersion
	}
	return ""
}

func (x *LinkedClusterNodeStatusResponse) GetLogLevel() LogLevel {
	if x != nil {
		return x.LogLevel
	}
	return LogLevel_NO_LEVEL
}

func (x *LinkedClusterNodeStatusResponse) GetActiveTime() *timestamppb.Timestamp {
	if x != nil {
		return x.ActiveTime
	}
	return nil
}

func (x *LinkedClusterNodeStatusResponse) GetRaftStatus() *RaftStatus {
	if x != nil {
		return x.RaftStatus
	}
	return nil
}

var File_vault_hcp_link_proto_node_status_status_proto protoreflect.FileDescriptor

var file_vault_hcp_link_proto_node_status_status_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2f, 0x68, 0x63, 0x70, 0x5f, 0x6c, 0x69, 0x6e, 0x6b,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x24, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x76, 0x61, 0x75, 0x6c, 0x74,
	0x2e, 0x68, 0x63, 0x70, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x26, 0x0a, 0x0a, 0x52, 0x61, 0x66, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x12, 0x18, 0x0a, 0x07, 0x49, 0x73, 0x56, 0x6f, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x07, 0x49, 0x73, 0x56, 0x6f, 0x74, 0x65, 0x72, 0x22, 0xcb, 0x06, 0x0a, 0x1f,
	0x4c, 0x69, 0x6e, 0x6b, 0x65, 0x64, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4e, 0x6f, 0x64,
	0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x69, 0x7a,
	0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61,
	0x6c, 0x69, 0x7a, 0x65, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x65, 0x61, 0x6c, 0x65, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x53, 0x65, 0x61, 0x6c, 0x65, 0x64, 0x12, 0x0c, 0x0a,
	0x01, 0x54, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x01, 0x54, 0x12, 0x0c, 0x0a, 0x01, 0x4e,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x01, 0x4e, 0x12, 0x1a, 0x0a, 0x08, 0x50, 0x72, 0x6f,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x50, 0x72, 0x6f,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x4e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x4e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x61,
	0x74, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x44,
	0x61, 0x74, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65,
	0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x44,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49,
	0x44, 0x12, 0x22, 0x0a, 0x0c, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x53, 0x65, 0x61,
	0x6c, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x53, 0x65, 0x61, 0x6c, 0x12, 0x20, 0x0a, 0x0b, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x54, 0x79, 0x70, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x53, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2a, 0x0a, 0x10, 0x52, 0x65, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x18, 0x0f, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x10, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x10, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x2c, 0x0a, 0x11, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x65, 0x73, 0x18, 0x11, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x4c, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x12, 0x28, 0x0a,
	0x0f, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x18, 0x12, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6e,
	0x67, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x12, 0x36, 0x0a, 0x16, 0x4f, 0x70, 0x65, 0x72, 0x61,
	0x74, 0x69, 0x6e, 0x67, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6e, 0x67, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x4a, 0x0a, 0x08, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x14, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x2e, 0x2e, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x76, 0x61,
	0x75, 0x6c, 0x74, 0x2e, 0x68, 0x63, 0x70, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x6e, 0x6f, 0x64,
	0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65,
	0x6c, 0x52, 0x08, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x3a, 0x0a, 0x0a, 0x41,
	0x63, 0x74, 0x69, 0x76, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x15, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x41, 0x63, 0x74,
	0x69, 0x76, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x50, 0x0a, 0x0a, 0x52, 0x61, 0x66, 0x74, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x16, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x68, 0x61,
	0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2e, 0x68, 0x63,
	0x70, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2e, 0x52, 0x61, 0x66, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x0a, 0x52,
	0x61, 0x66, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2a, 0x4d, 0x0a, 0x08, 0x4c, 0x6f, 0x67,
	0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x0c, 0x0a, 0x08, 0x4e, 0x4f, 0x5f, 0x4c, 0x45, 0x56, 0x45,
	0x4c, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x54, 0x52, 0x41, 0x43, 0x45, 0x10, 0x01, 0x12, 0x09,
	0x0a, 0x05, 0x44, 0x45, 0x42, 0x55, 0x47, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x49, 0x4e, 0x46,
	0x4f, 0x10, 0x03, 0x12, 0x08, 0x0a, 0x04, 0x57, 0x41, 0x52, 0x4e, 0x10, 0x04, 0x12, 0x09, 0x0a,
	0x05, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x05, 0x42, 0x3d, 0x5a, 0x3b, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70,
	0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2f, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2f, 0x68, 0x63, 0x70,
	0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6e, 0x6f, 0x64, 0x65,
	0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_vault_hcp_link_proto_node_status_status_proto_rawDescOnce sync.Once
	file_vault_hcp_link_proto_node_status_status_proto_rawDescData = file_vault_hcp_link_proto_node_status_status_proto_rawDesc
)

func file_vault_hcp_link_proto_node_status_status_proto_rawDescGZIP() []byte {
	file_vault_hcp_link_proto_node_status_status_proto_rawDescOnce.Do(func() {
		file_vault_hcp_link_proto_node_status_status_proto_rawDescData = protoimpl.X.CompressGZIP(file_vault_hcp_link_proto_node_status_status_proto_rawDescData)
	})
	return file_vault_hcp_link_proto_node_status_status_proto_rawDescData
}

var file_vault_hcp_link_proto_node_status_status_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_vault_hcp_link_proto_node_status_status_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_vault_hcp_link_proto_node_status_status_proto_goTypes = []interface{}{
	(LogLevel)(0),                           // 0: hashicorp.vault.hcp_link.node_status.LogLevel
	(*RaftStatus)(nil),                      // 1: hashicorp.vault.hcp_link.node_status.RaftStatus
	(*LinkedClusterNodeStatusResponse)(nil), // 2: hashicorp.vault.hcp_link.node_status.LinkedClusterNodeStatusResponse
	(*timestamppb.Timestamp)(nil),           // 3: google.protobuf.Timestamp
}
var file_vault_hcp_link_proto_node_status_status_proto_depIdxs = []int32{
	0, // 0: hashicorp.vault.hcp_link.node_status.LinkedClusterNodeStatusResponse.LogLevel:type_name -> hashicorp.vault.hcp_link.node_status.LogLevel
	3, // 1: hashicorp.vault.hcp_link.node_status.LinkedClusterNodeStatusResponse.ActiveTime:type_name -> google.protobuf.Timestamp
	1, // 2: hashicorp.vault.hcp_link.node_status.LinkedClusterNodeStatusResponse.RaftStatus:type_name -> hashicorp.vault.hcp_link.node_status.RaftStatus
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_vault_hcp_link_proto_node_status_status_proto_init() }
func file_vault_hcp_link_proto_node_status_status_proto_init() {
	if File_vault_hcp_link_proto_node_status_status_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_vault_hcp_link_proto_node_status_status_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RaftStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_vault_hcp_link_proto_node_status_status_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LinkedClusterNodeStatusResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_vault_hcp_link_proto_node_status_status_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_vault_hcp_link_proto_node_status_status_proto_goTypes,
		DependencyIndexes: file_vault_hcp_link_proto_node_status_status_proto_depIdxs,
		EnumInfos:         file_vault_hcp_link_proto_node_status_status_proto_enumTypes,
		MessageInfos:      file_vault_hcp_link_proto_node_status_status_proto_msgTypes,
	}.Build()
	File_vault_hcp_link_proto_node_status_status_proto = out.File
	file_vault_hcp_link_proto_node_status_status_proto_rawDesc = nil
	file_vault_hcp_link_proto_node_status_status_proto_goTypes = nil
	file_vault_hcp_link_proto_node_status_status_proto_depIdxs = nil
}
