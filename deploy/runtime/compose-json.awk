# Strict, bounded JSON extractor for the Docker Compose runtime wrapper.
#
# Modes:
#   env   - emit JSON strings for SERVICE's environment as "KEY=value"
#   value - emit compact canonical JSON for SERVICE/FIELD[/FIELD2], or the
#           ABSENT marker
#   array - emit every string item from a top-level JSON string array
#   object - emit every top-level string member as "KEY=value"
#   keys  - emit every top-level object key as its canonical JSON string
#   path  - emit compact canonical JSON at a length-framed object/array path;
#           components path1..path8 use literal object keys or #N array indexes
#   count - emit array|N or object|N for the selected path
#
# This parser deliberately accepts only the JSON shapes the wrapper needs. It
# never evaluates extracted data and rejects escaped object keys, duplicate
# object keys, malformed Unicode scalars, raw non-ASCII string bytes, trailing
# bytes, and oversized input. Object paths are length-framed tokens; a key that
# contains '/' or resembles another path can therefore never spoof structure.

function fail(code) {
    failed = code
    exit code
}

function skip_space(    character) {
    while (position <= text_length) {
        character = substr(text, position, 1)
        if (character != " " && character != "\t" && character != "\r" && character != "\n") break
        position++
    }
}

function key_path(path, key) {
    return path "K" length(key) ":" key ";"
}

function array_path(path, item_index) {
    return path "I" item_index ";"
}

function hex_value(hex,    cursor, character, digit, value) {
    value = 0
    for (cursor = 1; cursor <= 4; cursor++) {
        character = toupper(substr(hex, cursor, 1))
        digit = index("0123456789ABCDEF", character) - 1
        if (digit < 0) fail(63)
        value = value * 16 + digit
    }
    return value
}

function validate_unicode_scalar(hex,    value, following, following_value) {
    value = hex_value(hex)
    if (value >= 55296 && value <= 56319) {
        if (substr(text, position, 2) != "\\u") fail(87)
        following = substr(text, position + 2, 4)
        if (length(following) != 4 || following !~ /^[0-9A-Fa-f]{4}$/) fail(88)
        following_value = hex_value(following)
        if (following_value < 56320 || following_value > 57343) fail(89)
        position += 6
    } else if (value >= 56320 && value <= 57343) {
        fail(90)
    }
}

function parse_string(    start, character, escaped, hex) {
    if (substr(text, position, 1) != "\"") fail(61)
    start = position++
    parsed_plain = ""
    parsed_string_has_escape = 0
    while (position <= text_length) {
        character = substr(text, position++, 1)
        if (character == "\"") {
            parsed_raw = substr(text, start, position - start)
            return
        }
        if (character == "\\") {
            parsed_string_has_escape = 1
            if (position > text_length) fail(62)
            escaped = substr(text, position++, 1)
            if (escaped == "u") {
                hex = substr(text, position, 4)
                if (length(hex) != 4 || hex !~ /^[0-9A-Fa-f]{4}$/) fail(63)
                position += 4
                validate_unicode_scalar(hex)
            } else if (escaped !~ /^["\\\/bfnrt]$/) {
                fail(64)
            }
            continue
        }
        # LC_ALL=C is set by the caller. Requiring printable ASCII here makes
        # malformed UTF-8 and implementation-dependent locale decoding fail
        # closed; valid non-ASCII scalars must use checked JSON \u escapes.
        if (character !~ /^[ -~]$/) fail(65)
        parsed_plain = parsed_plain character
    }
    fail(66)
}

function compact_json(raw,    cursor, character, escaped, output) {
    escaped = 0
    in_string = 0
    output = ""
    for (cursor = 1; cursor <= length(raw); cursor++) {
        character = substr(raw, cursor, 1)
        if (in_string) {
            output = output character
            if (escaped) escaped = 0
            else if (character == "\\") escaped = 1
            else if (character == "\"") in_string = 0
            continue
        }
        if (character == "\"") {
            in_string = 1
            output = output character
        } else if (character != " " && character != "\t" && character != "\r" && character != "\n") {
            output = output character
        }
    }
    if (in_string || escaped) fail(67)
    return output
}

function parse_primitive(    remainder, token) {
    remainder = substr(text, position)
    if (match(remainder, /^(true|false|null)/)) {
        token = substr(remainder, 1, RLENGTH)
    } else if (match(remainder, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
        token = substr(remainder, 1, RLENGTH)
    } else {
        fail(68)
    }
    position += length(token)
    value_kind = "primitive"
}

function parse_array(path,    character, item_count) {
    if (substr(text, position, 1) != "[") fail(69)
    position++
    skip_space()
    if (substr(text, position, 1) == "]") {
        position++
        value_kind = "array"
        if (mode == "count" && path == selected_path) {
            print "array|0"
            selected_counts++
        }
        return
    }
    item_count = 0
    while (1) {
        parse_value(array_path(path, item_count), "")
        item_count++
        if (item_count > 100000) fail(70)
        skip_space()
        character = substr(text, position, 1)
        if (character == "]") {
            position++
            value_kind = "array"
            if (mode == "count" && path == selected_path) {
                print "array|" item_count
                selected_counts++
            }
            return
        }
        if (character != ",") fail(71)
        position++
        skip_space()
    }
}

function parse_object(path,    character, key, key_raw, next_path, count, object_id) {
    if (substr(text, position, 1) != "{") fail(72)
    position++
    skip_space()
    if (substr(text, position, 1) == "}") {
        position++
        value_kind = "object"
        if (mode == "count" && path == selected_path) {
            print "object|0"
            selected_counts++
        }
        return
    }
    object_id = ++object_serial
    count = 0
    while (1) {
        parse_string()
        if (parsed_string_has_escape) fail(73)
        key = parsed_plain
        key_raw = parsed_raw
        if (object_keys[object_id SUBSEP key]++) fail(74)
        if (mode == "keys" && path == "") {
            print key_raw
            object_key_items++
        }
        count++
        if (count > 100000) fail(75)
        skip_space()
        if (substr(text, position, 1) != ":") fail(76)
        position++
        next_path = key_path(path, key)
        parse_value(next_path, key)
        skip_space()
        character = substr(text, position, 1)
        if (character == "}") {
            position++
            value_kind = "object"
            if (mode == "count" && path == selected_path) {
                print "object|" count
                selected_counts++
            }
            return
        }
        if (character != ",") fail(77)
        position++
        skip_space()
    }
}

function parse_value(path, member_key,    character, start, raw) {
    skip_space()
    start = position
    character = substr(text, position, 1)
    if (character == "{") parse_object(path)
    else if (character == "[") parse_array(path)
    else if (character == "\"") {
        parse_string()
        value_kind = "string"
    } else parse_primitive()
    raw = substr(text, start, position - start)

    if (mode == "array" && path ~ /^I[0-9]+;$/) {
        if (value_kind != "string") fail(78)
        print parsed_raw
        array_items++
    }

    if (mode == "object" && path == key_path("", member_key)) {
        if (member_key == "" || member_key ~ /[=[:cntrl:]]/ || value_kind != "string") fail(98)
        print "\"" member_key "=" substr(parsed_raw, 2)
        object_items++
    }

    if (mode == "env" && path == key_path(environment_path, member_key)) {
        if (member_key !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || value_kind != "string") fail(79)
        # key cannot require JSON escaping under the accepted grammar. Splicing
        # the raw encoded value preserves every byte without eval or decoding.
        print "\"" member_key "=" substr(parsed_raw, 2)
        environment_items++
    }

    if ((mode == "env" || mode == "value") && path == service_path) service_found++
    if ((mode == "env" || mode == "value") && path == environment_path) {
        if (value_kind != "object") fail(91)
        environment_found++
    }
    if (mode == "value" && path == selected_path) {
        print compact_json(raw)
        selected_values++
    }
    if (mode == "path" && path == selected_path) {
        print compact_json(raw)
        selected_values++
    }
}

{
    text = text $0 "\n"
    if (length(text) > 2097152) fail(80)
}

END {
    if (failed) exit failed
    if (mode != "env" && mode != "value" && mode != "array" && mode != "path" && mode != "count" \
        && mode != "object" && mode != "keys") fail(81)
    text_length = length(text)
    position = 1
    if (mode == "array") {
        skip_space()
        if (substr(text, position, 4) == "null") position += 4
        else parse_array("")
    } else if (mode == "object" || mode == "keys") {
        skip_space()
        if (substr(text, position, 4) == "null") position += 4
        else parse_object("")
    } else if (mode == "path" || mode == "count") {
        if (mode == "path" && path_count !~ /^[1-8]$/) fail(94)
        if (mode == "count" && path_count !~ /^(0|[1-8])$/) fail(94)
        selected_path = ""
        for (path_index = 1; path_index <= path_count; path_index++) {
            path_component = (path_index == 1 ? path1 : \
                (path_index == 2 ? path2 : \
                (path_index == 3 ? path3 : \
                (path_index == 4 ? path4 : \
                (path_index == 5 ? path5 : \
                (path_index == 6 ? path6 : \
                (path_index == 7 ? path7 : path8)))))))
            if (path_component ~ /^#[0-9]+$/) {
                path_component_index = substr(path_component, 2)
                if (path_component_index !~ /^(0|[1-9][0-9]{0,5})$/) fail(95)
                selected_path = array_path(selected_path, path_component_index)
            } else {
                if (path_component == "" || length(path_component) > 128 \
                    || path_component ~ /[[:cntrl:]]/) fail(96)
                selected_path = key_path(selected_path, path_component)
            }
        }
        parse_value("", "")
    } else {
        if (service !~ /^[a-z0-9][a-z0-9_-]{0,63}$/) fail(82)
        if (mode == "value" && field !~ /^[a-z_][a-z0-9_]{0,63}$/) fail(83)
        if (mode == "value" && field2 != "" \
            && field2 !~ /^[a-z_][a-z0-9_]{0,63}$/) fail(93)
        services_path = key_path("", "services")
        service_path = key_path(services_path, service)
        environment_path = key_path(service_path, "environment")
        selected_path = key_path(service_path, field)
        if (field2 != "") selected_path = key_path(selected_path, field2)
        parse_value("", "")
    }
    skip_space()
    if (position <= text_length) fail(84)
    if (mode != "array" && mode != "object" && mode != "keys" \
        && mode != "path" && mode != "count" && service_found != 1) fail(85)
    if (mode == "env" && environment_found != 1) fail(92)
    if (mode == "value") {
        if (selected_values == 0) print "__BACKUPSHEEP_ABSENT__"
        else if (selected_values != 1) fail(86)
    }
    if (mode == "path") {
        if (allow_absent != "" && allow_absent != "0" && allow_absent != "1") fail(100)
        if (selected_values == 0 && allow_absent == "1") print "__BACKUPSHEEP_ABSENT__"
        else if (selected_values != 1) fail(97)
    }
    if (mode == "count" && selected_counts != 1) fail(99)
}
