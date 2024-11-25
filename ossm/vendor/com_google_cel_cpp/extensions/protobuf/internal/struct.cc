// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "extensions/protobuf/internal/struct.h"

#include <string>
#include <utility>

#include "google/protobuf/struct.pb.h"
#include "absl/base/attributes.h"
#include "absl/base/optimization.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "common/json.h"
#include "extensions/protobuf/internal/map_reflection.h"
#include "internal/casts.h"
#include "internal/overloaded.h"
#include "internal/status_macros.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/map_field.h"
#include "google/protobuf/message.h"
#include "google/protobuf/reflection.h"

namespace cel::extensions::protobuf_internal {

namespace {

// Gets the `Descriptor` for `message`, verifying that it is not `nullptr`.
absl::StatusOr<const google::protobuf::Descriptor*> GetDescriptor(
    const google::protobuf::Message& message) {
  const auto* descriptor = message.GetDescriptor();
  if (ABSL_PREDICT_FALSE(descriptor == nullptr)) {
    return absl::InternalError(
        absl::StrCat(message.GetTypeName(), " missing descriptor"));
  }
  return descriptor;
}

// Gets the `Reflection` for `message`, verifying that it is not `nullptr`.
absl::StatusOr<const google::protobuf::Reflection*> GetReflection(
    const google::protobuf::Message& message) {
  const auto* reflection = message.GetReflection();
  if (ABSL_PREDICT_FALSE(reflection == nullptr)) {
    return absl::InternalError(
        absl::StrCat(message.GetTypeName(), " missing reflection"));
  }
  return reflection;
}

// Gets the `FieldDescriptor` for `number` in `message`, verifying that it is
// not `nullptr`.
ABSL_ATTRIBUTE_NONNULL()
absl::StatusOr<const google::protobuf::FieldDescriptor*> FindFieldByNumber(
    const google::protobuf::Descriptor* descriptor, int number) {
  const auto* field = descriptor->FindFieldByNumber(number);
  if (ABSL_PREDICT_FALSE(field == nullptr)) {
    return absl::InternalError(
        absl::StrCat(descriptor->full_name(),
                     " missing descriptor for field number: ", number));
  }
  return field;
}

// Gets the `OneofDescriptor` for `name` in `message`, verifying that it is
// not `nullptr`.
ABSL_ATTRIBUTE_NONNULL()
absl::StatusOr<const google::protobuf::OneofDescriptor*> FindOneofByName(
    const google::protobuf::Descriptor* descriptor, absl::string_view name) {
  const auto* oneof = descriptor->FindOneofByName(name);
  if (ABSL_PREDICT_FALSE(oneof == nullptr)) {
    return absl::InternalError(absl::StrCat(
        descriptor->full_name(), " missing descriptor for oneof: ", name));
  }
  return oneof;
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldType(const google::protobuf::FieldDescriptor* field,
                            google::protobuf::FieldDescriptor::CppType type) {
  if (ABSL_PREDICT_FALSE(field->cpp_type() != type)) {
    return absl::InternalError(absl::StrCat(
        field->full_name(), " has unexpected type: ", field->cpp_type_name()));
  }
  return absl::OkStatus();
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldSingular(const google::protobuf::FieldDescriptor* field) {
  if (ABSL_PREDICT_FALSE(field->is_repeated() || field->is_map())) {
    return absl::InternalError(absl::StrCat(
        field->full_name(), " has unexpected cardinality: REPEATED"));
  }
  return absl::OkStatus();
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldRepeated(const google::protobuf::FieldDescriptor* field) {
  if (ABSL_PREDICT_FALSE(!field->is_repeated() && !field->is_map())) {
    return absl::InternalError(absl::StrCat(
        field->full_name(), " has unexpected cardinality: SINGULAR"));
  }
  return absl::OkStatus();
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldMap(const google::protobuf::FieldDescriptor* field) {
  if (ABSL_PREDICT_FALSE(!field->is_map())) {
    if (field->is_repeated()) {
      return absl::InternalError(
          absl::StrCat(field->full_name(),
                       " has unexpected type: ", field->cpp_type_name()));
    } else {
      return absl::InternalError(absl::StrCat(
          field->full_name(), " has unexpected cardinality: SINGULAR"));
    }
  }
  return absl::OkStatus();
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldEnumType(const google::protobuf::FieldDescriptor* field,
                                absl::string_view name) {
  CEL_RETURN_IF_ERROR(
      CheckFieldType(field, google::protobuf::FieldDescriptor::CPPTYPE_ENUM));
  if (ABSL_PREDICT_FALSE(field->enum_type()->full_name() != name)) {
    return absl::InternalError(absl::StrCat(
        field->full_name(),
        " has unexpected type: ", field->enum_type()->full_name()));
  }
  return absl::OkStatus();
}

ABSL_ATTRIBUTE_NONNULL()
absl::Status CheckFieldMessageType(const google::protobuf::FieldDescriptor* field,
                                   absl::string_view name) {
  CEL_RETURN_IF_ERROR(
      CheckFieldType(field, google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE));
  if (ABSL_PREDICT_FALSE(field->message_type()->full_name() != name)) {
    return absl::InternalError(absl::StrCat(
        field->full_name(),
        " has unexpected type: ", field->message_type()->full_name()));
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<Json> DynamicValueProtoToJson(const google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.Value");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::Value::descriptor())) {
    return GeneratedValueProtoToJson(
        google::protobuf::DownCastToGenerated<google::protobuf::Value>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  CEL_ASSIGN_OR_RETURN(const auto* kind_desc, FindOneofByName(desc, "kind"));
  const auto* value_desc =
      reflection->GetOneofFieldDescriptor(message, kind_desc);
  if (value_desc == nullptr) {
    return kJsonNull;
  }
  switch (value_desc->number()) {
    case google::protobuf::Value::kNullValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldEnumType(value_desc, "google.protobuf.NullValue"));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return kJsonNull;
    case google::protobuf::Value::kNumberValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldType(value_desc, google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return reflection->GetDouble(message, value_desc);
    case google::protobuf::Value::kStringValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldType(value_desc, google::protobuf::FieldDescriptor::CPPTYPE_STRING));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return reflection->GetCord(message, value_desc);
    case google::protobuf::Value::kBoolValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldType(value_desc, google::protobuf::FieldDescriptor::CPPTYPE_BOOL));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return reflection->GetBool(message, value_desc);
    case google::protobuf::Value::kStructValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldMessageType(value_desc, "google.protobuf.Struct"));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return DynamicStructProtoToJson(
          reflection->GetMessage(message, value_desc));
    case google::protobuf::Value::kListValueFieldNumber:
      CEL_RETURN_IF_ERROR(
          CheckFieldMessageType(value_desc, "google.protobuf.ListValue"));
      CEL_RETURN_IF_ERROR(CheckFieldSingular(value_desc));
      return DynamicListValueProtoToJson(
          reflection->GetMessage(message, value_desc));
    default:
      return absl::InternalError(
          absl::StrCat(value_desc->full_name(),
                       " has unexpected number: ", value_desc->number()));
  }
}

absl::StatusOr<Json> GeneratedValueProtoToJson(
    const google::protobuf::Value& message) {
  switch (message.kind_case()) {
    case google::protobuf::Value::KIND_NOT_SET:
      ABSL_FALLTHROUGH_INTENDED;
    case google::protobuf::Value::kNullValue:
      return kJsonNull;
    case google::protobuf::Value::kBoolValue:
      return message.bool_value();
    case google::protobuf::Value::kNumberValue:
      return message.number_value();
    case google::protobuf::Value::kStringValue:
      return absl::Cord(message.string_value());
    case google::protobuf::Value::kStructValue:
      return GeneratedStructProtoToJson(message.struct_value());
    case google::protobuf::Value::kListValue:
      return GeneratedListValueProtoToJson(message.list_value());
    default:
      return absl::InternalError(
          absl::StrCat("unexpected google.protobuf.Value oneof kind: ",
                       message.kind_case()));
  }
}

absl::StatusOr<Json> DynamicListValueProtoToJson(
    const google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.ListValue");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::ListValue::descriptor())) {
    return GeneratedListValueProtoToJson(
        google::protobuf::DownCastToGenerated<google::protobuf::ListValue>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  CEL_ASSIGN_OR_RETURN(
      const auto* values_field,
      FindFieldByNumber(desc, google::protobuf::ListValue::kValuesFieldNumber));
  CEL_RETURN_IF_ERROR(
      CheckFieldMessageType(values_field, "google.protobuf.Value"));
  CEL_RETURN_IF_ERROR(CheckFieldRepeated(values_field));
  const auto& repeated_field_ref =
      reflection->GetRepeatedFieldRef<google::protobuf::Message>(message, values_field);
  JsonArrayBuilder builder;
  builder.reserve(repeated_field_ref.size());
  for (const auto& element : repeated_field_ref) {
    CEL_ASSIGN_OR_RETURN(auto value, DynamicValueProtoToJson(element));
    builder.push_back(std::move(value));
  }
  return std::move(builder).Build();
}

absl::StatusOr<Json> GeneratedListValueProtoToJson(
    const google::protobuf::ListValue& message) {
  JsonArrayBuilder builder;
  builder.reserve(message.values_size());
  for (const auto& element : message.values()) {
    CEL_ASSIGN_OR_RETURN(auto value, GeneratedValueProtoToJson(element));
    builder.push_back(std::move(value));
  }
  return std::move(builder).Build();
}

absl::StatusOr<Json> DynamicStructProtoToJson(const google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.Struct");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::Struct::descriptor())) {
    return GeneratedStructProtoToJson(
        google::protobuf::DownCastToGenerated<google::protobuf::Struct>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  CEL_ASSIGN_OR_RETURN(
      const auto* fields_field,
      FindFieldByNumber(desc, google::protobuf::Struct::kFieldsFieldNumber));
  CEL_RETURN_IF_ERROR(CheckFieldMap(fields_field));
  CEL_RETURN_IF_ERROR(CheckFieldType(fields_field->message_type()->map_key(),
                                     google::protobuf::FieldDescriptor::CPPTYPE_STRING));
  CEL_RETURN_IF_ERROR(CheckFieldMessageType(
      fields_field->message_type()->map_value(), "google.protobuf.Value"));
  auto map_begin =
      protobuf_internal::MapBegin(*reflection, message, *fields_field);
  auto map_end = protobuf_internal::MapEnd(*reflection, message, *fields_field);
  JsonObjectBuilder builder;
  builder.reserve(
      protobuf_internal::MapSize(*reflection, message, *fields_field));
  for (; map_begin != map_end; ++map_begin) {
    CEL_ASSIGN_OR_RETURN(
        auto value,
        DynamicValueProtoToJson(map_begin.GetValueRef().GetMessageValue()));
    builder.insert_or_assign(absl::Cord(map_begin.GetKey().GetStringValue()),
                             std::move(value));
  }
  return std::move(builder).Build();
}

absl::StatusOr<Json> GeneratedStructProtoToJson(
    const google::protobuf::Struct& message) {
  JsonObjectBuilder builder;
  builder.reserve(message.fields_size());
  for (const auto& field : message.fields()) {
    CEL_ASSIGN_OR_RETURN(auto value, GeneratedValueProtoToJson(field.second));
    builder.insert_or_assign(absl::Cord(field.first), std::move(value));
  }
  return std::move(builder).Build();
}

absl::Status DynamicValueProtoFromJson(const Json& json,
                                       google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.Value");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::Value::descriptor())) {
    return GeneratedValueProtoFromJson(
        json, google::protobuf::DownCastToGenerated<google::protobuf::Value>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  return absl::visit(
      internal::Overloaded{
          [&message, &desc, &reflection](JsonNull) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* null_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kNullValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldEnumType(
                null_value_field, "google.protobuf.NullValue"));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(null_value_field));
            reflection->SetEnumValue(&message, null_value_field, 0);
            return absl::OkStatus();
          },
          [&message, &desc, &reflection](JsonBool value) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* bool_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kBoolValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldType(
                bool_value_field, google::protobuf::FieldDescriptor::CPPTYPE_BOOL));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(bool_value_field));
            reflection->SetBool(&message, bool_value_field, value);
            return absl::OkStatus();
          },
          [&message, &desc, &reflection](JsonNumber value) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* number_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kNumberValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldType(
                number_value_field, google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(number_value_field));
            reflection->SetDouble(&message, number_value_field, value);
            return absl::OkStatus();
          },
          [&message, &desc,
           &reflection](const JsonString& value) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* string_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kStringValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldType(
                string_value_field, google::protobuf::FieldDescriptor::CPPTYPE_STRING));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(string_value_field));
            reflection->SetString(&message, string_value_field,
                                  static_cast<std::string>(value));
            return absl::OkStatus();
          },
          [&message, &desc,
           &reflection](const JsonArray& value) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* list_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kListValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldMessageType(
                list_value_field, "google.protobuf.ListValue"));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(list_value_field));
            return DynamicListValueProtoFromJson(
                value, *reflection->MutableMessage(&message, list_value_field));
          },
          [&message, &desc,
           &reflection](const JsonObject& value) -> absl::Status {
            CEL_ASSIGN_OR_RETURN(
                const auto* struct_value_field,
                FindFieldByNumber(
                    desc, google::protobuf::Value::kStructValueFieldNumber));
            CEL_RETURN_IF_ERROR(CheckFieldMessageType(
                struct_value_field, "google.protobuf.Struct"));
            CEL_RETURN_IF_ERROR(CheckFieldSingular(struct_value_field));
            return DynamicStructProtoFromJson(
                value,
                *reflection->MutableMessage(&message, struct_value_field));
          }},
      json);
}

absl::Status GeneratedValueProtoFromJson(const Json& json,
                                         google::protobuf::Value& message) {
  return absl::visit(
      internal::Overloaded{
          [&message](JsonNull) {
            message.set_null_value(google::protobuf::NULL_VALUE);
            return absl::OkStatus();
          },
          [&message](JsonBool value) {
            message.set_bool_value(value);
            return absl::OkStatus();
          },
          [&message](JsonNumber value) {
            message.set_number_value(value);
            return absl::OkStatus();
          },
          [&message](const JsonString& value) {
            message.set_string_value(static_cast<std::string>(value));
            return absl::OkStatus();
          },
          [&message](const JsonArray& value) {
            return GeneratedListValueProtoFromJson(
                value, *message.mutable_list_value());
          },
          [&message](const JsonObject& value) {
            return GeneratedStructProtoFromJson(
                value, *message.mutable_struct_value());
          }},
      json);
}

absl::Status DynamicListValueProtoFromJson(const JsonArray& json,
                                           google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.ListValue");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::ListValue::descriptor())) {
    return GeneratedListValueProtoFromJson(
        json,
        google::protobuf::DownCastToGenerated<google::protobuf::ListValue>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  CEL_ASSIGN_OR_RETURN(
      const auto* values_field,
      FindFieldByNumber(desc, google::protobuf::ListValue::kValuesFieldNumber));
  CEL_RETURN_IF_ERROR(
      CheckFieldMessageType(values_field, "google.protobuf.Value"));
  CEL_RETURN_IF_ERROR(CheckFieldRepeated(values_field));
  auto repeated_field_ref =
      reflection->GetMutableRepeatedFieldRef<google::protobuf::Message>(&message,
                                                              values_field);
  repeated_field_ref.Clear();
  for (const auto& element : json) {
    auto scratch = absl::WrapUnique(repeated_field_ref.NewMessage());
    CEL_RETURN_IF_ERROR(DynamicValueProtoFromJson(element, *scratch));
    repeated_field_ref.Add(*scratch);
  }
  return absl::OkStatus();
}

absl::Status GeneratedListValueProtoFromJson(
    const JsonArray& json, google::protobuf::ListValue& message) {
  auto* elements = message.mutable_values();
  elements->Clear();
  elements->Reserve(static_cast<int>(json.size()));
  for (const auto& element : json) {
    CEL_RETURN_IF_ERROR(GeneratedValueProtoFromJson(element, *elements->Add()));
  }
  return absl::OkStatus();
}

absl::Status DynamicStructProtoFromJson(const JsonObject& json,
                                        google::protobuf::Message& message) {
  ABSL_DCHECK_EQ(message.GetTypeName(), "google.protobuf.Struct");
  CEL_ASSIGN_OR_RETURN(const auto* desc, GetDescriptor(message));
  if (ABSL_PREDICT_TRUE(desc == google::protobuf::Struct::descriptor())) {
    return GeneratedStructProtoFromJson(
        json, google::protobuf::DownCastToGenerated<google::protobuf::Struct>(message));
  }
  CEL_ASSIGN_OR_RETURN(const auto* reflection, GetReflection(message));
  CEL_ASSIGN_OR_RETURN(
      const auto* fields_field,
      FindFieldByNumber(desc, google::protobuf::Struct::kFieldsFieldNumber));
  CEL_RETURN_IF_ERROR(CheckFieldMap(fields_field));
  CEL_RETURN_IF_ERROR(CheckFieldType(fields_field->message_type()->map_key(),
                                     google::protobuf::FieldDescriptor::CPPTYPE_STRING));
  CEL_RETURN_IF_ERROR(CheckFieldMessageType(
      fields_field->message_type()->map_value(), "google.protobuf.Value"));
  for (const auto& entry : json) {
    google::protobuf::MapKey map_key;
    map_key.SetStringValue(static_cast<std::string>(entry.first));
    google::protobuf::MapValueRef map_value;
    protobuf_internal::InsertOrLookupMapValue(
        *reflection, &message, *fields_field, map_key, &map_value);
    CEL_RETURN_IF_ERROR(DynamicValueProtoFromJson(
        entry.second, *map_value.MutableMessageValue()));
  }
  return absl::OkStatus();
}

absl::Status GeneratedStructProtoFromJson(const JsonObject& json,
                                          google::protobuf::Struct& message) {
  auto* fields = message.mutable_fields();
  fields->clear();
  for (const auto& field : json) {
    CEL_RETURN_IF_ERROR(GeneratedValueProtoFromJson(
        field.second, (*fields)[static_cast<std::string>(field.first)]));
  }
  return absl::OkStatus();
}

}  // namespace cel::extensions::protobuf_internal
