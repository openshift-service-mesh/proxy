/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GOOGLE_PROTOBUF_UTIL_CONVERTER_PROTO_WRITER_H_
#define GOOGLE_PROTOBUF_UTIL_CONVERTER_PROTO_WRITER_H_

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/stubs/bytestream.h"
#include "google/protobuf/type.pb.h"
#include "google/protobuf/util/converter/datapiece.h"
#include "google/protobuf/util/converter/error_listener.h"
#include "google/protobuf/util/converter/structured_objectwriter.h"
#include "google/protobuf/util/converter/type_info.h"
#include "google/protobuf/util/type_resolver.h"

namespace google {
namespace protobuf {
namespace util {
namespace converter {

class ObjectLocationTracker;

// An ObjectWriter that can write protobuf bytes directly from writer events.
// This class does not support special types like Struct or Map. However, since
// this class supports raw protobuf, it can be used to provide support for
// special types by inheriting from it or by wrapping it.
//
// It also supports streaming.
class ProtoWriter : public StructuredObjectWriter {
 public:
  // Constructor. Does not take ownership of any parameter passed in.
  ProtoWriter(TypeResolver* type_resolver, const google::protobuf::Type& type,
              strings::ByteSink* output, ErrorListener* listener);
  ProtoWriter() = delete;
  ProtoWriter(const ProtoWriter&) = delete;
  ProtoWriter& operator=(const ProtoWriter&) = delete;
  ~ProtoWriter() override;

  // ObjectWriter methods.
  ProtoWriter* StartObject(absl::string_view name) override;
  ProtoWriter* EndObject() override;
  ProtoWriter* StartList(absl::string_view name) override;
  ProtoWriter* EndList() override;
  ProtoWriter* RenderBool(absl::string_view name, bool value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderInt32(absl::string_view name, int32_t value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderUint32(absl::string_view name, uint32_t value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderInt64(absl::string_view name, int64_t value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderUint64(absl::string_view name, uint64_t value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderDouble(absl::string_view name, double value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderFloat(absl::string_view name, float value) override {
    return RenderDataPiece(name, DataPiece(value));
  }
  ProtoWriter* RenderString(absl::string_view name,
                            absl::string_view value) override {
    return RenderDataPiece(name,
                           DataPiece(value, use_strict_base64_decoding()));
  }

  ProtoWriter* RenderBytes(absl::string_view name,
                           absl::string_view value) override {
    return RenderDataPiece(
        name, DataPiece(value, false, use_strict_base64_decoding()));
  }

  ProtoWriter* RenderNull(absl::string_view name) override {
    return RenderDataPiece(name, DataPiece::NullData());
  }

  // Renders a DataPiece 'value' into a field whose wire type is determined
  // from the given field 'name'.
  virtual ProtoWriter* RenderDataPiece(absl::string_view name,
                                       const DataPiece& data);

  // Returns the location tracker to use for tracking locations for errors.
  const LocationTrackerInterface& location() {
    return element_ != nullptr ? *element_ : *tracker_;
  }

  // When true, we finished writing to output a complete message.
  bool done() override { return done_; }

  // Returns the proto stream object.
  io::CodedOutputStream* stream() { return stream_.get(); }

  // Getters and mutators of invalid_depth_.
  void IncrementInvalidDepth() { ++invalid_depth_; }
  void DecrementInvalidDepth() { --invalid_depth_; }
  int invalid_depth() { return invalid_depth_; }

  ErrorListener* listener() { return listener_; }

  const TypeInfo* typeinfo() { return typeinfo_; }

  void set_ignore_unknown_fields(bool ignore_unknown_fields) {
    ignore_unknown_fields_ = ignore_unknown_fields;
  }

  bool ignore_unknown_fields() { return ignore_unknown_fields_; }

  void set_ignore_unknown_enum_values(bool ignore_unknown_enum_values) {
    ignore_unknown_enum_values_ = ignore_unknown_enum_values;
  }

  void set_use_lower_camel_for_enums(bool use_lower_camel_for_enums) {
    use_lower_camel_for_enums_ = use_lower_camel_for_enums;
  }

  void set_case_insensitive_enum_parsing(bool case_insensitive_enum_parsing) {
    case_insensitive_enum_parsing_ = case_insensitive_enum_parsing;
  }

  void set_use_json_name_in_missing_fields(
      bool use_json_name_in_missing_fields) {
    use_json_name_in_missing_fields_ = use_json_name_in_missing_fields;
  }

 protected:
  class ProtoElement : public BaseElement, public LocationTrackerInterface {
   public:
    // Constructor for the root element. No parent nor field.
    ProtoElement(const TypeInfo* typeinfo, const google::protobuf::Type& type,
                 ProtoWriter* enclosing);

    // Constructor for a field of an element.
    ProtoElement(ProtoElement* parent, const google::protobuf::Field* field,
                 const google::protobuf::Type& type, bool is_list);
    ProtoElement() = delete;
    ProtoElement(const ProtoElement&) = delete;
    ProtoElement& operator=(const ProtoElement&) = delete;

    ~ProtoElement() override {}

    // Called just before the destructor for clean up:
    //   - reports any missing required fields
    //   - computes the space needed by the size field, and augment the
    //     length of all parent messages by this additional space.
    //   - releases and returns the parent pointer.
    ProtoElement* pop();

    // Accessors
    // parent_field() may be nullptr if we are at root.
    const google::protobuf::Field* parent_field() const {
      return parent_field_;
    }
    const google::protobuf::Type& type() const { return type_; }

    // Registers field for accounting required fields.
    void RegisterField(const google::protobuf::Field* field);

    // To report location on error messages.
    std::string ToString() const override;

    ProtoElement* parent() const override {
      return static_cast<ProtoElement*>(BaseElement::parent());
    }

    // Returns true if the index is already taken by a preceding oneof input.
    bool IsOneofIndexTaken(int32_t index);

    // Marks the oneof 'index' as taken. Future inputs to this oneof will
    // generate an error.
    void TakeOneofIndex(int32_t index);

    bool proto3() { return proto3_; }

   private:
    // Used for access to variables of the enclosing instance of
    // ProtoWriter.
    ProtoWriter* ow_;

    // Describes the element as a field in the parent message.
    // parent_field_ is nullptr if and only if this element is the root element.
    const google::protobuf::Field* parent_field_;

    // TypeInfo to lookup types.
    const TypeInfo* typeinfo_;

    // Whether the type_ is proto3 or not.
    bool proto3_;

    // Additional variables if this element is a message:
    // (Root element is always a message).
    // type_             : the type of this element.
    // required_fields_  : set of required fields.
    // size_index_       : index into ProtoWriter::size_insert_
    //                     for later insertion of serialized message length.
    const google::protobuf::Type& type_;
    absl::flat_hash_set<const google::protobuf::Field*> required_fields_;
    const int size_index_;

    // Tracks position in repeated fields, needed for LocationTrackerInterface.
    int array_index_;

    // Set of oneof indices already seen for the type_. Used to validate
    // incoming messages so no more than one oneof is set.
    std::vector<bool> oneof_indices_;
  };

  // Container for inserting 'size' information at the 'pos' position.
  struct SizeInfo {
    const int pos;
    int size;
  };

  ProtoWriter(const TypeInfo* typeinfo, const google::protobuf::Type& type,
              strings::ByteSink* output, ErrorListener* listener);

  ProtoElement* element() override { return element_.get(); }

  // Helper methods for calling ErrorListener. See error_listener.h.
  void InvalidName(absl::string_view unknown_name, absl::string_view message);
  void InvalidValue(absl::string_view type_name, absl::string_view value);
  void MissingField(absl::string_view missing_name);

  // Common code for BeginObject() and BeginList() that does invalid_depth_
  // bookkeeping associated with name lookup.
  const google::protobuf::Field* BeginNamed(absl::string_view name,
                                            bool is_list);

  // Lookup the field in the current element. Looks in the base descriptor
  // and in any extension. This will report an error if the field cannot be
  // found when ignore_unknown_names_ is false or if multiple matching
  // extensions are found.
  const google::protobuf::Field* Lookup(absl::string_view name);

  // Lookup the field type in the type descriptor. Returns nullptr if the type
  // is not known.
  const google::protobuf::Type* LookupType(
      const google::protobuf::Field* field);

  // Write serialized output to the final output ByteSink, inserting all
  // the size information for nested messages that are missing from the
  // intermediate Cord buffer.
  void WriteRootMessage();

  // Helper method to write proto tags based on the given field.
  void WriteTag(const google::protobuf::Field& field);

  // Returns true if the field for type_ can be set as a oneof. If field is not
  // a oneof type, this function does nothing and returns true.
  // If another field for this oneof is already set, this function returns
  // false. It also calls the appropriate error callback.
  // unnormalized_name is used for error string.
  bool ValidOneof(const google::protobuf::Field& field,
                  absl::string_view unnormalized_name);

  // Returns true if the field is repeated.
  bool IsRepeated(const google::protobuf::Field& field);

  // Starts an object given the field and the enclosing type.
  ProtoWriter* StartObjectField(const google::protobuf::Field& field,
                                const google::protobuf::Type& type);

  // Starts a list given the field and the enclosing type.
  ProtoWriter* StartListField(const google::protobuf::Field& field,
                              const google::protobuf::Type& type);

  // Renders a primitive field given the field and the enclosing type.
  ProtoWriter* RenderPrimitiveField(const google::protobuf::Field& field,
                                    const google::protobuf::Type& type,
                                    const DataPiece& data);

 private:
  // Writes an ENUM field, including tag, to the stream.
  static absl::Status WriteEnum(int field_number, const DataPiece& data,
                                const google::protobuf::Enum* enum_type,
                                io::CodedOutputStream* stream,
                                bool use_lower_camel_for_enums,
                                bool case_insensitive_enum_parsing,
                                bool ignore_unknown_values);

  // Variables for describing the structure of the input tree:
  // master_type_: descriptor for the whole protobuf message.
  // typeinfo_ : the TypeInfo object to lookup types.
  const google::protobuf::Type& master_type_;
  const TypeInfo* typeinfo_;
  // Whether we own the typeinfo_ object.
  bool own_typeinfo_;

  // Indicates whether we finished writing root message completely.
  bool done_;

  // If true, don't report unknown field names to the listener.
  bool ignore_unknown_fields_;

  // If true, don't report unknown enum values to the listener.
  bool ignore_unknown_enum_values_;

  // If true, check if enum name in camel case or without underscore matches the
  // field name.
  bool use_lower_camel_for_enums_;

  // If true, check if enum name in UPPER_CASE matches the field name.
  bool case_insensitive_enum_parsing_;

  // If true, use the json name in missing fields errors.
  bool use_json_name_in_missing_fields_;

  // Variable for internal state processing:
  // element_    : the current element.
  // size_insert_: sizes of nested messages.
  //               pos  - position to insert the size field.
  //               size - size value to be inserted.
  std::unique_ptr<ProtoElement> element_;
  std::deque<SizeInfo> size_insert_;

  // Variables for output generation:
  // output_  : pointer to an external ByteSink for final user-visible output.
  // buffer_  : buffer holding partial message before being ready for output_.
  // adapter_ : internal adapter between CodedOutputStream and buffer_.
  // stream_  : wrapper for writing tags and other encodings in wire format.
  strings::ByteSink* output_;
  std::string buffer_;
  io::StringOutputStream adapter_;
  std::unique_ptr<io::CodedOutputStream> stream_;

  // Variables for error tracking and reporting:
  // listener_     : a place to report any errors found.
  // invalid_depth_: number of enclosing invalid nested messages.
  // tracker_      : the root location tracker interface.
  ErrorListener* listener_;
  int invalid_depth_;
  std::unique_ptr<LocationTrackerInterface> tracker_;
};

}  // namespace converter
}  // namespace util
}  // namespace protobuf
}  // namespace google

#endif  // GOOGLE_PROTOBUF_UTIL_CONVERTER_PROTO_WRITER_H_
