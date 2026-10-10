"""Versioned Tree-sitter heuristic rule tables for review-prioritization signals.

A rule match is a review lead, never a finding.  Name-based call rules are
``heuristic_inference``: they match callee text without resolving symbols.  Rules that observe an
exact construct (an annotation, an export, a literal insecure setting, a suppression directive) are
``observed_syntax``.  Comments and string literals never match a call rule because only call nodes
are inspected.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


RULES_IDENTITY = "appsec-review/review-heuristics/1"
OBSERVED = "observed_syntax"
HEURISTIC = "heuristic_inference"
SEMANTIC = "verified_semantic_path"

C_FAMILY = frozenset({"c", "cpp"})
JS_FAMILY = frozenset({"javascript", "typescript", "tsx"})
ALL = frozenset({"c", "cpp", "java", "csharp", "go", "javascript", "typescript", "tsx", "rust", "php"})


@dataclass(frozen=True, slots=True)
class CallRule:
    rule_id: str
    category: str
    surface: str
    grammars: frozenset[str]
    names: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    # A receiver-qualified call matches only when one qualifier names a segment of its receiver path
    # ("*" accepts any receiver; "*Suffix" matches a segment ending in Suffix).
    qualifiers: frozenset[str] = frozenset()
    # Unqualified calls match only when allowed, optionally only when the file imports a module.
    allow_bare: bool = False
    bare_imports: frozenset[str] = frozenset()


def _rule(rule_id: str, category: str, surface: str, grammars, names=(), *, prefixes=(), qualifiers=(),
          bare=False, imports=()) -> CallRule:
    return CallRule(rule_id, category, surface, frozenset(grammars), frozenset(names), tuple(prefixes),
                    frozenset(qualifiers), bare, frozenset(imports))


_DB = ("db", "tx", "conn", "connection", "session", "em", "entityManager", "repository", "repo", "collection",
       "stmt", "statement", "pdo", "knex", "prisma", "cursor", "pool", "client", "mysqli", "wpdb", "database",
       "sequelize", "jdbcTemplate", "context", "dbContext", "_context", "_db")
_FS = ("fs", "fsp", "promises", "os", "ioutil", "Files", "File", "Directory", "std", "fs_extra", "fse")

CALL_RULES: tuple[CallRule, ...] = (
    # --- sinks -------------------------------------------------------------------------------
    _rule("sink.command_exec.c-family", "sink", "command_exec", C_FAMILY,
          ("system", "popen", "_popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "ShellExecuteA",
           "ShellExecuteW", "CreateProcessA", "CreateProcessW", "WinExec"), bare=True),
    _rule("sink.command_exec.java", "sink", "command_exec", {"java"}, ("exec",), qualifiers=("getRuntime", "Runtime")),
    _rule("sink.command_exec.java-processbuilder", "sink", "command_exec", {"java"}, ("ProcessBuilder",), bare=True),
    _rule("sink.command_exec.csharp", "sink", "command_exec", {"csharp"}, ("Start",), qualifiers=("Process",)),
    _rule("sink.command_exec.go", "sink", "command_exec", {"go"}, ("Command", "CommandContext"), qualifiers=("exec",)),
    _rule("sink.command_exec.node", "sink", "command_exec", JS_FAMILY,
          ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"),
          qualifiers=("child_process", "childProcess", "cp"), bare=True, imports=("child_process", "node:child_process")),
    _rule("sink.command_exec.rust", "sink", "command_exec", {"rust"}, ("new",), qualifiers=("Command",)),
    _rule("sink.command_exec.php", "sink", "command_exec", {"php"},
          ("exec", "shell_exec", "system", "passthru", "proc_open", "popen", "pcntl_exec"), bare=True),
    _rule("sink.sql.go", "sink", "sql", {"go"},
          ("Exec", "ExecContext", "Query", "QueryContext", "QueryRow", "QueryRowContext"), qualifiers=_DB),
    _rule("sink.sql.java", "sink", "sql", {"java"},
          ("executeQuery", "executeUpdate", "execute", "addBatch", "executeLargeUpdate"),
          qualifiers=("createStatement", "statement", "stmt", "Statement", "jdbcTemplate")),
    _rule("sink.sql.csharp", "sink", "sql", {"csharp"},
          ("SqlCommand", "NpgsqlCommand", "MySqlCommand", "SqliteCommand", "OracleCommand"), bare=True),
    _rule("sink.sql.csharp-raw", "sink", "sql", {"csharp"},
          ("ExecuteSqlRaw", "ExecuteSqlRawAsync", "FromSqlRaw", "ExecuteSqlCommand", "SqlQueryRaw"), qualifiers=_DB + ("Database",)),
    _rule("sink.sql.php", "sink", "sql", {"php"}, ("mysqli_query", "mysql_query", "pg_query", "sqlite_query"), bare=True),
    _rule("sink.sql.php-member", "sink", "sql", {"php"}, ("query", "exec", "prepare", "multi_query"), qualifiers=_DB),
    _rule("sink.sql.node", "sink", "sql", JS_FAMILY, ("query", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "execute"),
          qualifiers=_DB),
    _rule("sink.sql.rust", "sink", "sql", {"rust"}, ("query", "query_as", "sql_query", "execute"),
          qualifiers=("sqlx", "diesel", "conn", "db", "tx", "connection")),
    _rule("sink.deserialization.java", "sink", "deserialization", {"java"}, ("ObjectInputStream", "XMLDecoder"),
          bare=True),
    _rule("sink.deserialization.java-read", "sink", "deserialization", {"java"}, ("readObject", "readUnshared", "fromXML"),
          qualifiers=("input", "in", "ois", "stream", "xstream", "XStream", "*InputStream")),
    _rule("sink.deserialization.csharp", "sink", "deserialization", {"csharp"},
          ("BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter", "ObjectStateFormatter"),
          bare=True),
    _rule("sink.deserialization.php", "sink", "deserialization", {"php"}, ("unserialize",), bare=True),
    _rule("sink.deserialization.node", "sink", "deserialization", JS_FAMILY, ("unserialize", "deserialize"),
          qualifiers=("serialize", "nodeSerialize", "v8", "serialijse")),
    _rule("sink.eval.node", "sink", "code_eval", JS_FAMILY, ("eval", "Function"), bare=True),
    _rule("sink.eval.node-vm", "sink", "code_eval", JS_FAMILY,
          ("runInNewContext", "runInThisContext", "runInContext", "compileFunction"), qualifiers=("vm",)),
    _rule("sink.eval.php", "sink", "code_eval", {"php"}, ("eval", "create_function", "assert"), bare=True),
    _rule("sink.eval.java", "sink", "code_eval", {"java"}, ("eval",), qualifiers=("engine", "scriptEngine", "ScriptEngine")),
    _rule("sink.memory.c-family", "sink", "memory", C_FAMILY,
          ("memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "gets", "alloca",
           "wcscpy", "wcscat", "lstrcpyA", "lstrcpyW"), bare=True),
    _rule("sink.file_path.c-family", "sink", "file_path", C_FAMILY,
          ("fopen", "freopen", "open", "openat", "unlink", "remove", "rename", "realpath"), bare=True),
    _rule("sink.file_path.go", "sink", "file_path", {"go"},
          ("Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "ReadDir"),
          qualifiers=("os", "ioutil")),
    _rule("sink.file_path.java", "sink", "file_path", {"java"},
          ("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"), bare=True),
    _rule("sink.file_path.java-nio", "sink", "file_path", {"java"},
          ("readAllBytes", "readString", "write", "writeString", "newInputStream", "newOutputStream", "delete", "get"),
          qualifiers=("Files", "Paths")),
    _rule("sink.file_path.csharp", "sink", "file_path", {"csharp"},
          ("ReadAllText", "ReadAllBytes", "WriteAllText", "WriteAllBytes", "Open", "OpenRead", "OpenWrite", "Delete",
           "AppendAllText"), qualifiers=("File",)),
    _rule("sink.file_path.node", "sink", "file_path", JS_FAMILY,
          ("readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "unlink",
           "unlinkSync", "sendFile", "download", "appendFile", "appendFileSync"), qualifiers=("fs", "fsp", "promises", "res")),
    _rule("sink.file_path.php", "sink", "file_path", {"php"},
          ("fopen", "file_get_contents", "file_put_contents", "readfile", "unlink", "file", "move_uploaded_file"), bare=True),
    _rule("sink.file_path.rust", "sink", "file_path", {"rust"},
          ("open", "create", "read_to_string", "read", "write", "remove_file", "remove_dir_all"), qualifiers=("File", "fs")),
    _rule("sink.outbound.go", "sink", "outbound_request", {"go"}, ("Get", "Post", "PostForm", "Head", "NewRequest"),
          qualifiers=("http",)),
    _rule("sink.outbound.node", "sink", "outbound_request", JS_FAMILY, ("fetch",), bare=True),
    _rule("sink.outbound.node-client", "sink", "outbound_request", JS_FAMILY, ("get", "post", "put", "request"),
          qualifiers=("axios", "got", "http", "https", "superagent", "needle")),
    _rule("sink.outbound.java", "sink", "outbound_request", {"java"},
          ("openConnection", "getForObject", "postForObject", "exchange", "send"),
          qualifiers=("url", "URL", "restTemplate", "httpClient", "client")),
    _rule("sink.outbound.csharp", "sink", "outbound_request", {"csharp"},
          ("GetAsync", "PostAsync", "SendAsync", "GetStringAsync", "DownloadString"),
          qualifiers=("client", "httpClient", "_httpClient", "_client", "http", "webClient")),
    _rule("sink.outbound.php", "sink", "outbound_request", {"php"}, ("curl_exec", "curl_init", "fsockopen"), bare=True),
    _rule("sink.outbound.rust", "sink", "outbound_request", {"rust"}, ("get", "post"), qualifiers=("reqwest",)),
    _rule("sink.outbound.c-family", "sink", "outbound_request", C_FAMILY, ("curl_easy_perform", "connect"), bare=True),
    _rule("sink.html.go", "sink", "html_output", {"go"}, ("HTML", "JS", "HTMLAttr"), qualifiers=("template",)),
    _rule("sink.html.csharp", "sink", "html_output", {"csharp"}, ("Raw",), qualifiers=("Html",)),
    _rule("sink.html.node", "sink", "html_output", JS_FAMILY, ("write", "writeln"), qualifiers=("document",)),
    _rule("sink.redirect.go", "sink", "redirect", {"go"}, ("Redirect",), qualifiers=("http",)),
    _rule("sink.redirect.node", "sink", "redirect", JS_FAMILY, ("redirect",), qualifiers=("res", "response", "ctx", "reply")),
    _rule("sink.redirect.java", "sink", "redirect", {"java"}, ("sendRedirect",), qualifiers=("response", "resp", "res")),
    _rule("sink.redirect.csharp", "sink", "redirect", {"csharp"}, ("Redirect",), qualifiers=("Response",)),
    # --- untrusted ingress, parsers, validators, middleware ------------------------------------
    _rule("ingress.read.c-family", "ingress", "untrusted_input", C_FAMILY,
          ("recv", "recvfrom", "recvmsg", "fgets", "gets", "scanf", "fscanf", "getenv"), bare=True),
    _rule("ingress.read.go", "ingress", "untrusted_input", {"go"},
          ("FormValue", "PostFormValue", "FormFile", "Query", "Cookie", "ParseForm", "ParseMultipartForm"),
          qualifiers=("r", "req", "request", "URL", "c", "ctx")),
    _rule("ingress.read.java", "ingress", "untrusted_input", {"java"},
          ("getParameter", "getParameterValues", "getHeader", "getInputStream", "getReader", "getQueryString",
           "getCookies"), qualifiers=("request", "req", "httpRequest", "servletRequest")),
    _rule("ingress.read.rust", "ingress", "untrusted_input", {"rust"}, ("args", "var", "vars", "stdin"),
          qualifiers=("env", "io")),
    _rule("ingress.read.php", "ingress", "untrusted_input", {"php"}, ("getallheaders", "apache_request_headers"), bare=True),
    _rule("parser.json", "parser", "json", ALL,
          ("parse", "Unmarshal", "readValue", "readTree", "fromJson", "DeserializeObject", "json_decode", "from_str",
           "from_slice", "from_reader", "Deserialize", "DeserializeAsync"),
          qualifiers=("JSON", "json", "objectMapper", "mapper", "ObjectMapper", "gson", "Gson", "JsonConvert",
                      "JsonSerializer", "serde_json", "simd_json")),
    _rule("parser.json-php", "parser", "json", {"php"}, ("json_decode",), bare=True),
    _rule("parser.decoder", "parser", "json", {"go"}, ("Decode",), qualifiers=("NewDecoder", "decoder", "dec")),
    _rule("parser.yaml", "parser", "yaml", ALL, ("load", "safeLoad", "parse", "from_str", "yaml_parse", "Deserialize"),
          qualifiers=("yaml", "YAML", "jsyaml", "serde_yaml", "Yaml", "deserializer"), bare=False),
    _rule("parser.yaml-php", "parser", "yaml", {"php"}, ("yaml_parse",), bare=True),
    _rule("parser.url", "parser", "url", ALL, ("Parse", "ParseRequestURI", "parse_url", "URL", "Uri", "parse"),
          qualifiers=("url", "Url", "urllib"), bare=False),
    _rule("parser.protobuf", "parser", "protobuf", ALL, ("Unmarshal", "parseFrom", "decode", "ParseFrom"),
          qualifiers=("proto", "Parser", "protobuf")),
    _rule("validator.call", "validator", "validation", ALL,
          ("filter_var", "filter_input", "htmlspecialchars", "htmlentities", "strip_tags", "escapeHtml", "sanitizeHtml"),
          prefixes=("validate", "Validate", "sanitize", "Sanitize", "sanitise"), bare=True),
    _rule("validator.qualified", "validator", "validation", ALL,
          ("parse", "safeParse", "validate", "validateSync", "IsValid", "TryValidateObject", "sanitize", "escape",
           "Clean", "Abs", "Rel"),
          prefixes=("validate", "Validate", "sanitize", "Sanitize"),
          qualifiers=("validator", "Validator", "*Schema", "*schema", "DOMPurify", "purify", "ModelState", "Joi", "yup",
                      "Validation", "Validator", "filepath")),
    _rule("middleware.node", "middleware", "request_pipeline", JS_FAMILY, ("use",),
          qualifiers=("app", "router", "server", "api", "fastify")),
    _rule("middleware.csharp", "middleware", "request_pipeline", {"csharp"},
          ("UseAuthentication", "UseAuthorization", "UseMiddleware", "UseCors", "UseWhen", "Use"), qualifiers=("app", "builder")),
    _rule("middleware.php", "middleware", "request_pipeline", {"php"}, ("middleware", "withoutMiddleware"), qualifiers=("Route", "route", "router", "this")),
    # --- privilege shifts ------------------------------------------------------------------------
    _rule("privilege.impersonation.posix", "privilege_shift", "impersonation", ALL,
          ("setuid", "seteuid", "setgid", "setegid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
           "initgroups", "Setuid", "Seteuid", "Setgid", "Setegid", "Setresuid", "posix_setuid", "posix_seteuid",
           "posix_setgid"), bare=True, qualifiers=("syscall", "unix", "libc", "nix", "process", "os")),
    _rule("privilege.impersonation.windows", "privilege_shift", "impersonation", ALL,
          ("ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient", "ImpersonateSelf", "LogonUserA", "LogonUserW",
           "LogonUser", "SetThreadToken", "RevertToSelf", "CreateProcessAsUserA", "CreateProcessAsUserW",
           "CreateProcessWithLogonW", "DuplicateTokenEx", "Impersonate", "RunImpersonated", "RunImpersonatedAsync"),
          bare=True, qualifiers=("WindowsIdentity", "identity", "NativeMethods", "windows")),
    _rule("privilege.elevation.java", "privilege_shift", "privileged_action", {"java"}, ("doPrivileged", "doAs"),
          qualifiers=("AccessController", "Subject")),
    _rule("privilege.access_control_bypass.spring", "privilege_shift", "access_control_bypass", {"java"},
          ("permitAll", "anonymous"), qualifiers=("authorizeRequests", "authorizeHttpRequests", "requestMatchers",
                                                  "antMatchers", "mvcMatchers", "anyRequest", "http", "auth")),
    _rule("privilege.access_control_bypass.csrf", "privilege_shift", "access_control_bypass", {"java"}, ("disable",),
          qualifiers=("csrf",)),
    _rule("privilege.access_control_bypass.aspnet", "privilege_shift", "access_control_bypass", {"csharp"},
          ("AllowAnonymous",), qualifiers=("app", "group", "endpoints", "builder", "MapGet", "MapPost")),
    # --- wrapper surfaces (external libraries with sensitive behavior) -----------------------------
    _rule("wrapper.xml", "sensitive_wrapper", "xml", ALL,
          ("xmlReadMemory", "xmlReadFile", "xmlReadDoc", "xmlParseMemory", "xmlParseFile", "xmlCtxtReadMemory",
           "XML_Parse", "SAXReader", "XmlDocument", "XmlTextReader", "XPathDocument", "DOMParser", "XMLParser",
           "simplexml_load_string", "simplexml_load_file", "DOMDocument", "xml_parse"), bare=True),
    _rule("wrapper.xml-member", "sensitive_wrapper", "xml", ALL,
          ("LoadXml", "loadXML", "parseXml", "parseXmlString", "parseString", "createXMLStreamReader", "newDocumentBuilder",
           "newSAXParser"), qualifiers=("*",)),
    _rule("wrapper.xml-factory", "sensitive_wrapper", "xml", ALL, ("newInstance", "newFactory", "Create", "parse"),
          qualifiers=("DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory",
                      "SchemaFactory", "XMLReaderFactory", "XmlReader", "roxmltree", "libxmljs", "xml2js")),
    _rule("wrapper.xml-decode", "sensitive_wrapper", "xml", {"go", "rust"}, ("Unmarshal", "NewDecoder", "parse", "from_str"),
          qualifiers=("xml", "roxmltree", "quick_xml", "serde_xml_rs")),
    _rule("wrapper.image", "sensitive_wrapper", "image", ALL,
          ("png_create_read_struct", "png_read_info", "png_read_image", "jpeg_read_header", "stbi_load",
           "stbi_load_from_memory", "TIFFOpen", "MagickReadImage", "MagickReadImageBlob", "gdImageCreateFromPng",
           "gdImageCreateFromJpeg", "imread", "imdecode", "FromStream", "FromFile", "Bitmap", "sharp", "imagecreatefromstring",
           "imagecreatefromjpeg", "imagecreatefrompng", "imagecreatefromgif", "getimagesize", "Imagick", "readImage",
           "readImageBlob", "load_from_memory", "DecodeConfig"),
          bare=True, qualifiers=("ImageIO", "Image", "image", "png", "jpeg", "gif", "cv", "jimp", "Jimp", "ImageReader",
                                 "Imagick", "*imagick")),
    _rule("wrapper.image-decode", "sensitive_wrapper", "image", {"go", "java", "rust"}, ("Decode", "read", "open"),
          qualifiers=("image", "png", "jpeg", "gif", "ImageIO", "ImageReader")),
    _rule("wrapper.crypto", "sensitive_wrapper", "crypto", ALL,
          ("SecretKeySpec", "openssl_encrypt", "openssl_decrypt", "openssl_sign", "openssl_verify", "crypt",
           "mcrypt_encrypt", "mcrypt_decrypt", "hash_hmac", "md5", "sha1", "RAND_bytes", "RNGCryptoServiceProvider",
           "HMACSHA256", "HMACSHA1"),
          prefixes=("EVP_", "RSA_", "AES_", "DES_", "SHA1_", "SHA256_", "MD5_", "mbedtls_", "sodium_", "crypto_",
                    "BCrypt", "CryptEncrypt", "CryptDecrypt"), bare=True),
    _rule("wrapper.crypto-member", "sensitive_wrapper", "crypto", ALL,
          ("getInstance", "createCipheriv", "createDecipheriv", "createCipher", "createHash", "createHmac", "createSign",
           "createVerify", "pbkdf2", "pbkdf2Sync", "randomBytes", "NewCipher", "NewGCM", "NewCBCEncrypter",
           "NewCBCDecrypter", "New", "Sum", "Create", "sign", "verify", "encrypt", "decrypt", "Encrypt", "Decrypt",
           "GenerateKey", "SignPKCS1v15", "VerifyPKCS1v15"),
          qualifiers=("Cipher", "MessageDigest", "KeyGenerator", "Signature", "Mac", "KeyStore", "crypto", "subtle",
                      "aes", "cipher", "md5", "sha1", "sha256", "rsa", "hmac", "Aes", "RSA", "SHA1", "MD5", "SHA256",
                      "jwt", "jsonwebtoken", "jose", "openssl", "ring", "aes_gcm", "Crypto", "bcrypt", "ecdsa", "ed25519")),
    _rule("wrapper.regex", "sensitive_wrapper", "regex", ALL,
          ("Regex", "RegExp", "preg_match", "preg_match_all", "preg_replace", "preg_replace_callback", "preg_split",
           "regcomp", "regex_match", "regex_search", "regex_replace"), bare=True),
    _rule("wrapper.regex-member", "sensitive_wrapper", "regex", ALL,
          ("compile", "matches", "IsMatch", "Match", "Matches", "Replace", "Split", "Compile", "MustCompile",
           "MatchString", "new", "regex_match", "regex_search", "regex_replace"),
          qualifiers=("Pattern", "Regex", "regexp", "RegexBuilder")),
    _rule("wrapper.regex-cpp", "sensitive_wrapper", "regex", C_FAMILY, ("regex_match", "regex_search", "regex_replace"),
          qualifiers=("std",)),
    _rule("wrapper.ffi", "sensitive_wrapper", "ffi", ALL,
          ("dlopen", "dlsym", "LoadLibraryA", "LoadLibraryW", "LoadLibrary", "GetProcAddress"), bare=True),
    _rule("wrapper.ffi-member", "sensitive_wrapper", "ffi", ALL,
          ("loadLibrary", "load", "cdef", "Library", "func", "ForeignFunction", "Load", "GetDelegateForFunctionPointer"),
          qualifiers=("System", "FFI", "ffi", "koffi", "Marshal", "NativeLibrary")),
    _rule("wrapper.deserialization", "sensitive_wrapper", "deserialization", ALL,
          ("ObjectInputStream", "XMLDecoder", "BinaryFormatter", "SoapFormatter", "unserialize"), bare=True),
    _rule("wrapper.deserialization-member", "sensitive_wrapper", "deserialization", ALL,
          ("fromXML", "readObject", "Deserialize"),
          qualifiers=("input", "ois", "xstream", "XStream", "serialize", "formatter", "BinaryFormatter", "*InputStream")),
    # --- state mutation ---------------------------------------------------------------------------
    _rule("state.transaction", "state_mutation", "transaction", ALL,
          ("Begin", "BeginTx", "BeginTransaction", "BeginTransactionAsync", "beginTransaction", "startTransaction",
           "setAutoCommit", "transaction", "$transaction"), qualifiers=_DB + ("DB", "Database")),
    _rule("state.transaction-end", "state_mutation", "transaction_end", ALL, ("commit", "Commit", "rollback", "Rollback"),
          qualifiers=_DB + ("DB", "Database")),
    _rule("state.db_write", "state_mutation", "db_write", ALL,
          ("executeUpdate", "executeBatch", "ExecuteNonQuery", "ExecuteNonQueryAsync", "SaveChanges", "SaveChangesAsync",
           "persist", "insertOne", "insertMany", "updateOne", "updateMany", "deleteOne", "deleteMany", "bulkWrite"),
          bare=False, qualifiers=_DB + ("createStatement",)),
    _rule("state.db_write-generic", "state_mutation", "db_write", ALL,
          ("Exec", "ExecContext", "exec", "execute", "save", "insert", "update", "delete", "remove", "merge", "upsert",
           "create", "destroy"), qualifiers=_DB),
    _rule("state.fs_write", "state_mutation", "fs_write", ALL,
          ("WriteFile", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "fwrite", "fputs",
           "file_put_contents", "writeString", "WriteAllText", "WriteAllBytes", "AppendAllText", "unlink", "unlinkSync",
           "rmSync", "Remove", "RemoveAll", "Rename", "rename", "renameSync", "mkdir", "mkdirSync", "Mkdir", "MkdirAll",
           "CreateDirectory", "Delete", "remove_file", "create_dir_all", "write", "move_uploaded_file", "copy"),
          prefixes=(), bare=False, qualifiers=_FS),
    _rule("state.fs_write-c", "state_mutation", "fs_write", C_FAMILY | {"php"},
          ("fwrite", "fputs", "unlink", "rename", "remove", "mkdir", "rmdir", "file_put_contents", "ofstream"), bare=True),
    # --- manual serialization (custom parsing) -----------------------------------------------------
    _rule("parsing.manual_serialization", "custom_parsing", "manual_serialization", ALL,
          ("from_be_bytes", "from_le_bytes", "to_be_bytes", "to_le_bytes", "from_ne_bytes", "Uint16", "Uint32",
           "Uint64", "PutUint16", "PutUint32", "PutUint64", "ntohl", "htonl", "ntohs", "htons", "pack", "unpack",
           "getInt", "getShort", "getLong", "putInt", "putShort", "putLong", "ToInt32", "ToUInt32", "ToInt16",
           "readUInt32BE", "readUInt32LE", "readUInt16BE", "readUInt16LE", "writeUInt32BE", "writeUInt32LE",
           "readInt32BE", "readInt32LE", "ReadUInt32", "ReadUInt16", "ReadInt32", "readInt", "readShort", "readFully"),
          bare=True, qualifiers=("u8", "u16", "u32", "u64", "i32", "i64", "BigEndian", "LittleEndian", "binary", "buf",
                                 "buffer", "Buffer", "bb", "ByteBuffer", "BitConverter", "reader", "BinaryReader",
                                 "in", "dis", "data", "stream")),
)

# Route registration calls: receiver-qualified verbs whose first argument is a literal path.
ROUTE_VERBS = {
    "javascript": frozenset({"get", "post", "put", "delete", "patch", "all", "route", "options", "head"}),
    "go": frozenset({"HandleFunc", "Handle", "GET", "POST", "PUT", "DELETE", "PATCH", "Get", "Post", "Put", "Delete",
                     "Patch", "Any"}),
    "csharp": frozenset({"MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods", "Map"}),
    "rust": frozenset({"route", "service"}),
    "php": frozenset({"get", "post", "put", "delete", "patch", "any", "match"}),
}
ROUTE_VERBS["typescript"] = ROUTE_VERBS["tsx"] = ROUTE_VERBS["javascript"]

# Annotations, attributes, and decorators (observed syntax).
ANNOTATIONS: dict[str, tuple[tuple[str, str, str], ...]] = {
    # name: ((rule_id, category, surface), ...)
    "GetMapping": (("annotation.route", "ingress", "route_handler"), ("annotation.route-api", "public_api", "route")),
    "RequestBody": (("annotation.request-binding", "ingress", "request_binding"),),
    "RequestParam": (("annotation.request-binding", "ingress", "request_binding"),),
    "PathVariable": (("annotation.request-binding", "ingress", "request_binding"),),
    "RequestHeader": (("annotation.request-binding", "ingress", "request_binding"),),
    "ModelAttribute": (("annotation.request-binding", "ingress", "request_binding"),),
    "FromBody": (("annotation.request-binding", "ingress", "request_binding"),),
    "FromQuery": (("annotation.request-binding", "ingress", "request_binding"),),
    "FromRoute": (("annotation.request-binding", "ingress", "request_binding"),),
    "FromForm": (("annotation.request-binding", "ingress", "request_binding"),),
    "FromHeader": (("annotation.request-binding", "ingress", "request_binding"),),
    "PermitAll": (("annotation.access-control-bypass", "privilege_shift", "access_control_bypass"),),
    "AnonymousAllowed": (("annotation.access-control-bypass", "privilege_shift", "access_control_bypass"),),
    "AllowAnonymous": (("annotation.access-control-bypass", "privilege_shift", "access_control_bypass"),),
    "IgnoreAntiforgeryToken": (("annotation.csrf-bypass", "privilege_shift", "access_control_bypass"),),
    "CrossOrigin": (("annotation.cors", "privilege_shift", "cross_origin"),),
    "Valid": (("annotation.validation", "validator", "validation"),),
    "Validated": (("annotation.validation", "validator", "validation"),),
    "JsonProperty": (("annotation.schema", "public_api", "schema"),),
    "JsonCreator": (("annotation.schema", "public_api", "schema"),),
    "XmlRootElement": (("annotation.schema", "public_api", "schema"),),
    "Entity": (("annotation.schema", "public_api", "schema"),),
    "DataContract": (("annotation.schema", "public_api", "schema"),),
    "DataMember": (("annotation.schema", "public_api", "schema"),),
    "JsonPropertyName": (("annotation.schema", "public_api", "schema"),),
    "Serializable": (("annotation.schema", "public_api", "schema"),),
    "ApiController": (("annotation.controller", "public_api", "route"),),
    "RestController": (("annotation.controller", "public_api", "route"),),
    "Controller": (("annotation.controller", "public_api", "route"),),
    "DllImport": (("annotation.ffi", "sensitive_wrapper", "ffi"),),
    "LibraryImport": (("annotation.ffi", "sensitive_wrapper", "ffi"),),
}
for _verb in ("PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping", "GET", "POST", "PUT",
              "DELETE", "PATCH", "Path", "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route", "Get",
              "Post", "Put", "Delete", "Patch"):
    ANNOTATIONS[_verb] = ANNOTATIONS["GetMapping"]
RUST_ROUTE_ATTRIBUTES = frozenset({"get", "post", "put", "delete", "patch", "route", "head"})
RUST_SCHEMA_DERIVES = re.compile(r"\b(Serialize|Deserialize)\b")
JS_ROUTE_RECEIVERS = frozenset({"app", "router", "server", "api", "routes", "fastify", "route"})
JS_INGRESS_OBJECTS = frozenset({"req", "request", "ctx"})
JS_INGRESS_PROPERTIES = frozenset({"body", "query", "params", "headers", "cookies", "files", "rawBody", "file"})
GO_INGRESS_OBJECTS = frozenset({"r", "req", "request"})
GO_INGRESS_FIELDS = frozenset({"Body", "Form", "PostForm", "MultipartForm", "Header", "URL"})
CSHARP_INGRESS_PROPERTIES = frozenset({"Query", "Form", "Body", "Headers", "Cookies", "QueryString"})
PHP_SUPERGLOBALS = frozenset({"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_ENV"})
RUST_INGRESS_EXTRACTORS = re.compile(r"^(web::)?(Json|Query|Form|Path|Multipart|Bytes)\s*<")

# --- suppression directives ------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SuppressionRule:
    rule_id: str
    pattern: re.Pattern[str]
    tool: str
    category: str  # compiler | lint | type | security
    scope: str     # line | next_line | block_start | block_end | file | declaration | expression


def _s(rule_id: str, pattern: str, tool: str, category: str, scope: str) -> SuppressionRule:
    return SuppressionRule(rule_id, re.compile(pattern), tool, category, scope)


COMMENT_SUPPRESSIONS: tuple[SuppressionRule, ...] = (
    _s("suppression.nosemgrep", r"\bnosemgrep\b", "semgrep", "security", "line"),
    _s("suppression.nosec", r"#nosec\b", "gosec", "security", "line"),
    _s("suppression.codeql", r"\b(lgtm|codeql)\s*\[", "codeql", "security", "line"),
    _s("suppression.coverity", r"\bcoverity\s*\[", "coverity", "security", "next_line"),
    _s("suppression.flawfinder", r"\bflawfinder:\s*ignore\b", "flawfinder", "security", "line"),
    _s("suppression.deepcode", r"\bdeepcode\s+ignore\b", "snyk-code", "security", "next_line"),
    _s("suppression.nolint-next", r"\bNOLINTNEXTLINE\b", "clang-tidy", "lint", "next_line"),
    _s("suppression.nolint-begin", r"\bNOLINTBEGIN\b", "clang-tidy", "lint", "block_start"),
    _s("suppression.nolint-end", r"\bNOLINTEND\b", "clang-tidy", "lint", "block_end"),
    _s("suppression.nolint", r"\bNOLINT\b(?!NEXTLINE|BEGIN|END)", "clang-tidy", "lint", "line"),
    _s("suppression.cppcheck", r"\bcppcheck-suppress\b", "cppcheck", "lint", "next_line"),
    _s("suppression.golangci", r"//\s*nolint\b", "golangci-lint", "lint", "line"),
    _s("suppression.staticcheck", r"//\s*lint:(ignore|file-ignore)\b", "staticcheck", "lint", "next_line"),
    _s("suppression.go-directive", r"//go:(nocheckptr|linkname|nosplit|norace)\b", "go-compiler", "compiler", "declaration"),
    _s("suppression.eslint-next", r"\beslint-disable-next-line\b", "eslint", "lint", "next_line"),
    _s("suppression.eslint-line", r"\beslint-disable-line\b", "eslint", "lint", "line"),
    _s("suppression.eslint-block", r"\beslint-disable(?![-\w])", "eslint", "lint", "block_start"),
    _s("suppression.tslint", r"\btslint:disable", "tslint", "lint", "block_start"),
    _s("suppression.jshint", r"\bjshint\s+ignore\b", "jshint", "lint", "block_start"),
    _s("suppression.coverage", r"\b(istanbul|c8|v8)\s+ignore\b", "coverage", "lint", "next_line"),
    _s("suppression.ts-ignore", r"@ts-(ignore|expect-error)\b", "typescript", "type", "next_line"),
    _s("suppression.ts-nocheck", r"@ts-nocheck\b", "typescript", "type", "file"),
    _s("suppression.nosonar", r"\bNOSONAR\b", "sonar", "lint", "line"),
    _s("suppression.noinspection", r"//\s*noinspection\b", "intellij", "lint", "next_line"),
    _s("suppression.checkstyle", r"\bCHECKSTYLE[:.]?\s*OFF\b", "checkstyle", "lint", "block_start"),
    _s("suppression.resharper", r"\bReSharper\s+disable\b", "resharper", "lint", "block_start"),
    _s("suppression.phpcs", r"\bphpcs:(ignore|disable)\b", "phpcs", "lint", "line"),
    _s("suppression.phpcs-legacy", r"@codingStandardsIgnore(Line|Start|File)?\b", "phpcs", "lint", "line"),
    _s("suppression.psalm", r"@psalm-suppress\b", "psalm", "type", "declaration"),
    _s("suppression.phpstan", r"@phpstan-ignore(-next-line|-line)?\b", "phpstan", "type", "next_line"),
)
# A suppressed rule name with any of these markers is a security-check suppression.
SECURITY_MARKERS = re.compile(
    r"(?i)(secur|insecure|cert-|cwe|cve|gosec|\bG\d{3}\b|semgrep|codeql|taint|inject|xss|xxe|ssrf|csrf|crypt|"
    r"detect-|unsafe|\bCA(2\d{3}|3\d{3}|5\d{3})\b|\bSCS\d{4}\b|path[_-]?traversal|sql|command)")
JAVA_COMPILER_KEYS = frozenset({"unchecked", "rawtypes", "deprecation", "removal", "serial", "cast", "fallthrough",
                                "static", "try", "varargs", "dep-ann", "divzero", "empty", "finally", "overrides",
                                "path", "processing", "this-escape", "unused", "all", "preview", "restricted"})
