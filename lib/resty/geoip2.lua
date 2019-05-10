local ffi = require('ffi')
local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_metatype = ffi.metatype
local ffi_gc = ffi.gc
local ffi_typeof = ffi.typeof

ffi.cdef[[
typedef long ssize_t;

typedef struct MMDB_ipv4_start_node_s {
    uint16_t netmask;
    uint32_t node_value;
} MMDB_ipv4_start_node_s;

typedef unsigned int mmdb_uint128_t __attribute__ ((__mode__(TI)));

typedef struct MMDB_entry_s {
    struct MMDB_s *mmdb;
    uint32_t offset;
} MMDB_entry_s;

typedef struct MMDB_lookup_result_s {
    bool found_entry;
    MMDB_entry_s entry;
    uint16_t netmask;
} MMDB_lookup_result_s;

/* This is a pointer into the data section for a given IP address lookup */
typedef struct MMDB_entry_data_s {
    bool has_data;
    union {
        uint32_t pointer;
        const char *utf8_string;
        double double_value;
        const uint8_t *bytes;
        uint16_t uint16;
        uint32_t uint32;
        int32_t int32;
        uint64_t uint64;
        mmdb_uint128_t uint128;
        bool boolean;
        float float_value;
    };
    /* This is a 0 if a given entry cannot be found. This can only happen
     * when a call to MMDB_(v)get_value() asks for hash keys or array
     * indices that don't exist. */
    uint32_t offset;
    /* This is the next entry in the data section, but it's really only
     * relevant for entries that part of a larger map or array
     * struct. There's no good reason for an end user to look at this
     * directly. */
    uint32_t offset_to_next;
    /* This is only valid for strings, utf8_strings or binary data */
    uint32_t data_size;
    /* This is an MMDB_DATA_TYPE_* constant */
    uint32_t type;
} MMDB_entry_data_s;

/* This is the return type when someone asks for all the entry data in a map or array */
typedef struct MMDB_entry_data_list_s {
    MMDB_entry_data_s entry_data;
    struct MMDB_entry_data_list_s *next;
    void *pool;
} MMDB_entry_data_list_s;

typedef struct MMDB_description_s {
    const char *language;
    const char *description;
} MMDB_description_s;

typedef struct MMDB_metadata_s {
    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    const char *database_type;
    struct {
        size_t count;
        const char **names;
    } languages;
    uint16_t binary_format_major_version;
    uint16_t binary_format_minor_version;
    uint64_t build_epoch;
    struct {
        size_t count;
        MMDB_description_s **descriptions;
    } description;
} MMDB_metadata_s;

typedef struct MMDB_s {
    uint32_t flags;
    const char *filename;
    ssize_t file_size;
    const uint8_t *file_content;
    const uint8_t *data_section;
    uint32_t data_section_size;
    const uint8_t *metadata_section;
    uint32_t metadata_section_size;
    uint16_t full_record_byte_size;
    uint16_t depth;
    MMDB_ipv4_start_node_s ipv4_start_node;
    MMDB_metadata_s metadata;
} MMDB_s;

typedef struct MMDB_search_node_s {
    uint64_t left_record;
    uint64_t right_record;
    uint8_t left_record_type;
    uint8_t right_record_type;
    MMDB_entry_s left_record_entry;
    MMDB_entry_s right_record_entry;
} MMDB_search_node_s;

typedef char* pchar;

int MMDB_open(const char *const filename, uint32_t flags,
              MMDB_s *const mmdb);

MMDB_lookup_result_s MMDB_lookup_string(MMDB_s *const mmdb,
                                               const char *const ipstr,
                                               int *const gai_error,
                                               int *const mmdb_error);

int MMDB_read_node(MMDB_s *const mmdb, uint32_t node_number,
                   MMDB_search_node_s *const node);

int MMDB_get_value(MMDB_entry_s *const start,
                   MMDB_entry_data_s *const entry_data,
                   ...);

int MMDB_vget_value(MMDB_entry_s *const start,
                    MMDB_entry_data_s *const entry_data,
                    va_list va_path);

int MMDB_aget_value(MMDB_entry_s *const start,
                    MMDB_entry_data_s *const entry_data,
                    const char *const *const path);

int MMDB_get_metadata_as_entry_data_list(
    MMDB_s *const mmdb, MMDB_entry_data_list_s **const entry_data_list);

int MMDB_get_entry_data_list(
    MMDB_entry_s *start, MMDB_entry_data_list_s **const entry_data_list);

void MMDB_free_entry_data_list(
    MMDB_entry_data_list_s *const entry_data_list);

void MMDB_close(MMDB_s *const mmdb);

const char *MMDB_lib_version(void);

const char *MMDB_strerror(int error_code);

const char *gai_strerror(int errcode);
]]

local select = select
local setmetatable = setmetatable
local tostring = tostring

local ok, new_tab = pcall(require, 'table.new')
if not ok or type(new_tab) ~= 'function' then
    new_tab = function (narr, nrec) return {} end
end

local _M = {}
_M.version = '0.0.2'

local mmdb = ffi.load('libmaxminddb')
local db = ffi_new('MMDB_s')
local initialized = false

local MMDB_SUCCESS = 0
local MMDB_FILE_OPEN_ERROR = 1
local MMDB_CORRUPT_SEARCH_TREE_ERROR = 2
local MMDB_INVALID_METADATA_ERROR = 3
local MMDB_IO_ERROR = 4
local MMDB_OUT_OF_MEMORY_ERROR = 5
local MMDB_UNKNOWN_DATABASE_FORMAT_ERROR = 6
local MMDB_INVALID_DATA_ERROR = 7
local MMDB_INVALID_LOOKUP_PATH_ERROR = 8
local MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR = 9
local MMDB_INVALID_NODE_NUMBER_ERROR = 10
local MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR = 11

local MMDB_DATA_TYPE_EXTENDED = 0
local MMDB_DATA_TYPE_POINTER = 1
local MMDB_DATA_TYPE_UTF8_STRING = 2
local MMDB_DATA_TYPE_DOUBLE = 3
local MMDB_DATA_TYPE_BYTES = 4
local MMDB_DATA_TYPE_UINT16 = 5
local MMDB_DATA_TYPE_UINT32 = 6
local MMDB_DATA_TYPE_MAP = 7
local MMDB_DATA_TYPE_INT32 = 8
local MMDB_DATA_TYPE_UINT64 = 9
local MMDB_DATA_TYPE_UINT128 = 10
local MMDB_DATA_TYPE_ARRAY = 11
local MMDB_DATA_TYPE_CONTAINER = 12
local MMDB_DATA_TYPE_END_MARKER = 13
local MMDB_DATA_TYPE_BOOLEAN = 14
local MMDB_DATA_TYPE_FLOAT = 15

local MMDB_MODE_MMAP = ffi_new('uint32_t', 1)

local function mmdb_strerror(rc)
    return ffi_str(mmdb.MMDB_strerror(rc))
end

local function gai_strerror(rc)
    return ffi_str(C.gai_strerror(rc))
end

function _M.init(db_path)
    if not initialized then
        local status = mmdb.MMDB_open(db_path, MMDB_MODE_MMAP, db)

        if status ~= MMDB_SUCCESS then
            return mmdb_strerror(status)
        end

        initialized = true

        ffi_gc(db, mmdb.MMDB_close)
    end
end

function _M.initialized()
    return initialized
end

-- pack2 packs the vararg into an table as a one-based array, while skipping nil elements.
-- So the length of the returned array is available via '#' operator.
local function pack2(...)
    local n = select('#', ...)
    local i = 1
    local t = new_tab(n, 0)
    for j = 1, n do
        local v = select(j, ...)
        if v then
            t[i] = v
            i = i + 1
        end
    end
    return t
end

local int_p = ffi_typeof('int[1]')
local MMDB_lookup_result_s = ffi_typeof('MMDB_lookup_result_s')
local MMDB_entry_data_s = ffi_typeof('MMDB_entry_data_s[1]')
local const_char_pp = ffi_typeof('const char *[?]')

local MMDB_entry_data_list_s = ffi_typeof('MMDB_entry_data_list_s')

local lookup_result_mt = {
    __index = {
        get_value = function(self, ...)
            local fields = pack2(...)
            local n = #fields

            if n == 0 then
                return nil
            end

            local entry_data_p = ffi_new(MMDB_entry_data_s)
            local fs = ffi_new(const_char_pp, n + 1, fields)
            -- This is required due to LuaJIT's table initializers' rule described as follows.
            -- A VLA is only initialized with the element(s) given in the table. Depending on the use case, you may need to explicitly add a NULL or 0 terminator to a VLA.
            fs[n] = nil
            local status = mmdb.MMDB_aget_value(self.entry, entry_data_p, fs)

            if status ~= MMDB_SUCCESS then
                -- TODO: consider returning error detail to the client
                return nil, ffi_str(mmdb.MMDB_strerror(status))
            end

            local entry_data = entry_data_p[0]

            if not entry_data.has_data then
                return nil
            end

            -- Non-string result is not expected. Maybe due to inappropriate query.
            if entry_data.type ~= MMDB_DATA_TYPE_UTF8_STRING then
                return nil
            end

            return ffi_str(entry_data.utf8_string, entry_data.data_size)
        end,
    },
    __tostring = function(self)
        return 'MMDB_lookup_result_s(' ..
            'found_entry: ' .. tostring(self.found_entry) .. ', ' ..
            'entry: ' .. tostring(self.entry) .. ', ' ..
            'netmask: ' .. tostring(self.netmask) .. ')'
    end,
}

ffi_metatype(MMDB_lookup_result_s, lookup_result_mt)

function _M.lookup(ip)
    if not initialized then
        return nil, 'not initialized'
    end

    local gai_error = ffi_new(int_p)
    local mmdb_error = ffi_new(int_p)

    local result = mmdb.MMDB_lookup_string(db, ip, gai_error, mmdb_error)

    if gai_error[0] ~= 0 then
        return nil, 'getaddrinfo failed: ' .. gai_strerror(gai_error[0])
    end

    if mmdb_error[0] ~= MMDB_SUCCESS then
        return nil, 'lookup failed: ' .. mmdb_strerror(mmdb_error[0])
    end

    if not result.found_entry then
        return nil
    end

    return result
end

function _M.lookup_country_code(ip)
  local result = _M.lookup(ip)
  if err then
    return nil, err
  end
  if not result then
    return nil, 'not found'
  end
  local country_code = result:get_value('country', 'iso_code')
  if not country_code then
    return nil, 'not found'
  end
  return country_code, nil
end

return _M
