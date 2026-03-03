/**
 * witnesscalc.cpp - Shared library interface for witness calculation
 * 
 * Provides C FFI entry point for calling from Rust/JNI via dlopen.
 * No subprocess needed - loads and calls directly.
 * 
 * Build as: libmembership.so (shared library)
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <vector>

using json = nlohmann::json;

#include "calcwit.hpp"
#include "circom.hpp"

// Forward declarations from main.cpp logic
Circom_Circuit* loadCircuit(std::string const &datFileName);
void loadJsonFromString(Circom_CalcWit *ctx, const char* jsonStr, unsigned long jsonLen);
int writeWitnessToBuffer(Circom_CalcWit *ctx, unsigned char* buffer, unsigned long* bufferSize);

// ============================================================================
// Circuit loading (same as main.cpp)
// ============================================================================

Circom_Circuit* loadCircuit(std::string const &datFileName) {
    Circom_Circuit *circuit = new Circom_Circuit;

    int fd;
    struct stat sb;

    fd = open(datFileName.c_str(), O_RDONLY);
    if (fd == -1) {
        return nullptr;
    }
    
    if (fstat(fd, &sb) == -1) {
        close(fd);
        return nullptr;
    }

    u8* bdata = (u8*)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (bdata == MAP_FAILED) {
        return nullptr;
    }

    circuit->InputHashMap = new HashSignalInfo[get_size_of_input_hashmap()];
    uint dsize = get_size_of_input_hashmap()*sizeof(HashSignalInfo);
    memcpy((void *)(circuit->InputHashMap), (void *)bdata, dsize);

    circuit->witness2SignalList = new u64[get_size_of_witness()];
    uint inisize = dsize;    
    dsize = get_size_of_witness()*sizeof(u64);
    memcpy((void *)(circuit->witness2SignalList), (void *)(bdata+inisize), dsize);

    circuit->circuitConstants = new FrElement[get_size_of_constants()];
    if (get_size_of_constants()>0) {
        inisize += dsize;
        dsize = get_size_of_constants()*sizeof(FrElement);
        memcpy((void *)(circuit->circuitConstants), (void *)(bdata+inisize), dsize);
    }

    std::map<u32,IOFieldDefPair> templateInsId2IOSignalInfo1;
    if (get_size_of_io_map()>0) {
        u32 index[get_size_of_io_map()];
        inisize += dsize;
        dsize = get_size_of_io_map()*sizeof(u32);
        memcpy((void *)index, (void *)(bdata+inisize), dsize);
        inisize += dsize;
        u32 dataiomap[(sb.st_size-inisize)/sizeof(u32)];
        memcpy((void *)dataiomap, (void *)(bdata+inisize), sb.st_size-inisize);
        u32* pu32 = dataiomap;
        for (int i = 0; i < get_size_of_io_map(); i++) {
            u32 n = *pu32;
            IOFieldDefPair p;
            p.len = n;
            IOFieldDef defs[n];
            pu32 += 1;
            for (u32 j = 0; j < n; j++){
                defs[j].offset=*pu32;
                u32 len = *(pu32+1);
                defs[j].len = len;
                defs[j].lengths = new u32[len];
                memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));
                pu32 += len + 2;
                defs[j].size=*pu32;
                defs[j].busId=*(pu32+1);
                pu32 += 2;
            }
            p.defs = (IOFieldDef*)calloc(p.len, sizeof(IOFieldDef));
            for (u32 j = 0; j < p.len; j++){
                p.defs[j] = defs[j];
            }
            templateInsId2IOSignalInfo1[index[i]] = p;
        }
    }

    circuit->templateInsId2IOSignalInfo = std::move(templateInsId2IOSignalInfo1);
    munmap(bdata, sb.st_size);
    
    return circuit;
}

// ============================================================================
// JSON parsing helpers (adapted from main.cpp)
// ============================================================================

static void json2FrElements(json val, std::vector<FrElement>& v) {
    if (!val.is_array()) {
        FrElement fe;
        std::string s;
        if (val.is_string()) {
            s = val.get<std::string>();
        } else if (val.is_number()) {
            double d = val.get<double>();
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(0) << d;
            s = oss.str();
        } else {
            s = "0";
        }
        Fr_str2element(&fe, s.c_str(), 10);
        v.push_back(fe);
    } else {
        for (uint i = 0; i < val.size(); i++) {
            json2FrElements(val[i], v);
        }
    }
}

static json::value_t check_type(std::string prefix, json &in) {
    if (in.is_array() && in.size() > 0) {
        json::value_t t = in[0].type();
        for (uint i = 1; i < in.size(); i++) {
            if (in[i].type() != t) {
                return json::value_t::discarded;
            }
        }
        return t;
    }
    return json::value_t::null;
}

static void qualify_input(std::string prefix, json &in, json &in1);

static void qualify_input_list(std::string prefix, json &in, json &in1) {
    if (in.is_array()) {
        for (uint i = 0; i < in.size(); i++) {
            std::string new_prefix = prefix + "[" + std::to_string(i) + "]";
            qualify_input_list(new_prefix, in[i], in1);
        }
    } else {
        qualify_input(prefix, in, in1);
    }
}

static void qualify_input(std::string prefix, json &in, json &in1) {
    if (in.is_array()) {
        if (in.size() > 0) {
            json::value_t t = check_type(prefix, in);
            if (t == json::value_t::object) {
                qualify_input_list(prefix, in, in1);
            } else {
                in1[prefix] = in;
            }
        } else {
            in1[prefix] = in;
        }
    } else if (in.is_object()) {
        for (json::iterator it = in.begin(); it != in.end(); ++it) {
            std::string new_prefix = prefix.length() == 0 ? it.key() : prefix + "." + it.key();
            qualify_input(new_prefix, it.value(), in1);
        }
    } else {
        in1[prefix] = in;
    }
}

static u64 fnv1a(std::string s) {
    u64 hash = 0xCBF29CE484222325LL;
    for (char c : s) {
        hash ^= (u64)c;
        hash *= 0x100000001B3LL;
    }
    return hash;
}

void loadJsonFromString(Circom_CalcWit *ctx, const char* jsonStr, unsigned long jsonLen) {
    std::string jsonString(jsonStr, jsonLen);
    std::istringstream inStream(jsonString);
    json jin;
    inStream >> jin;
    json j;

    std::string prefix = "";
    qualify_input(prefix, jin, j);

    u64 nItems = j.size();
    if (nItems == 0) {
        ctx->tryRunCircuit();
    }
    
    for (json::iterator it = j.begin(); it != j.end(); ++it) {
        u64 h = fnv1a(it.key());
        std::vector<FrElement> v;
        json2FrElements(it.value(), v);
        uint signalSize = ctx->getInputSignalSize(h);
        
        if (v.size() != signalSize) {
            throw std::runtime_error("Signal size mismatch for " + it.key());
        }
        
        for (uint i = 0; i < v.size(); i++) {
            ctx->setInputSignal(h, i, v[i]);
        }
    }
}

// ============================================================================
// Witness output to buffer
// ============================================================================

int writeWitnessToBuffer(Circom_CalcWit *ctx, unsigned char* buffer, unsigned long* bufferSize) {
    uint Nwtns = get_size_of_witness();
    uint n8 = Fr_N64 * 8;
    
    // Calculate required size: header + section1 + section2
    // Header: 4 (magic) + 4 (version) + 4 (nSections) = 12
    // Section1: 4 (id) + 8 (len) + 4 (n8) + n8 (q) + 4 (nVars) = 20 + n8
    // Section2: 4 (id) + 8 (len) + n8*Nwtns (data) = 12 + n8*Nwtns
    unsigned long requiredSize = 12 + (20 + n8) + (12 + (unsigned long)n8 * Nwtns);
    
    if (*bufferSize < requiredSize) {
        *bufferSize = requiredSize;
        return -1;  // Buffer too small
    }
    
    unsigned char* ptr = buffer;
    
    // Magic
    memcpy(ptr, "wtns", 4);
    ptr += 4;
    
    // Version
    u32 version = 2;
    memcpy(ptr, &version, 4);
    ptr += 4;
    
    // nSections
    u32 nSections = 2;
    memcpy(ptr, &nSections, 4);
    ptr += 4;
    
    // Section 1 header
    u32 idSection1 = 1;
    memcpy(ptr, &idSection1, 4);
    ptr += 4;
    
    u64 idSection1length = 8 + n8;
    memcpy(ptr, &idSection1length, 8);
    ptr += 8;
    
    // n8
    memcpy(ptr, &n8, 4);
    ptr += 4;
    
    // Field modulus q
    memcpy(ptr, Fr_q.longVal, n8);
    ptr += n8;
    
    // nVars
    u32 nVars = (u32)Nwtns;
    memcpy(ptr, &nVars, 4);
    ptr += 4;
    
    // Section 2 header
    u32 idSection2 = 2;
    memcpy(ptr, &idSection2, 4);
    ptr += 4;
    
    u64 idSection2length = (u64)n8 * (u64)Nwtns;
    memcpy(ptr, &idSection2length, 8);
    ptr += 8;
    
    // Witness values
    FrElement v;
    for (uint i = 0; i < Nwtns; i++) {
        ctx->getWitness(i, &v);
        Fr_toLongNormal(&v, &v);
        memcpy(ptr, v.longVal, n8);
        ptr += n8;
    }
    
    *bufferSize = requiredSize;
    return 0;  // Success
}

// ============================================================================
// Public C API
// ============================================================================

extern "C" {

/**
 * Calculate witness for the membership circuit.
 * 
 * @param dat_path      Path to the .dat file (circuit data)
 * @param json_input    Input JSON string
 * @param json_len      Length of JSON string
 * @param wtns_buffer   Output buffer for witness (caller allocated)
 * @param wtns_size     In: buffer size, Out: actual witness size
 * @param error_msg     Buffer for error message (caller allocated, can be NULL)
 * @param error_msg_size Size of error message buffer
 * 
 * @return 0 on success, negative on error:
 *         -1: buffer too small (wtns_size updated with required size)
 *         -2: failed to load circuit
 *         -3: failed to parse JSON
 *         -4: missing inputs
 *         -5: other error
 */
int witnesscalc_membership(
    const char* dat_path,
    const char* json_input,
    unsigned long json_len,
    unsigned char* wtns_buffer,
    unsigned long* wtns_size,
    char* error_msg,
    unsigned long error_msg_size
) {
    try {
        // Load circuit
        Circom_Circuit* circuit = loadCircuit(std::string(dat_path));
        if (!circuit) {
            if (error_msg && error_msg_size > 0) {
                snprintf(error_msg, error_msg_size, "Failed to load circuit from %s", dat_path);
            }
            return -2;
        }
        
        // Create calculation context
        Circom_CalcWit* ctx = new Circom_CalcWit(circuit);
        
        // Load inputs from JSON
        try {
            loadJsonFromString(ctx, json_input, json_len);
        } catch (std::exception& e) {
            if (error_msg && error_msg_size > 0) {
                snprintf(error_msg, error_msg_size, "JSON parse error: %s", e.what());
            }
            delete ctx;
            delete circuit;
            return -3;
        }
        
        // Check all inputs set
        if (ctx->getRemaingInputsToBeSet() != 0) {
            if (error_msg && error_msg_size > 0) {
                snprintf(error_msg, error_msg_size, 
                    "Missing inputs: %llu of %u set",
                    get_main_input_signal_no() - ctx->getRemaingInputsToBeSet(),
                    get_main_input_signal_no());
            }
            delete ctx;
            delete circuit;
            return -4;
        }
        
        // Write witness to buffer
        int result = writeWitnessToBuffer(ctx, wtns_buffer, wtns_size);
        
        delete ctx;
        delete circuit;
        
        return result;
        
    } catch (std::exception& e) {
        if (error_msg && error_msg_size > 0) {
            snprintf(error_msg, error_msg_size, "Exception: %s", e.what());
        }
        return -5;
    }
}

/**
 * Get the expected witness buffer size for this circuit.
 * Call this first to allocate the right buffer size.
 */
unsigned long witnesscalc_membership_size() {
    uint Nwtns = get_size_of_witness();
    uint n8 = Fr_N64 * 8;
    return 12 + (20 + n8) + (12 + (unsigned long)n8 * Nwtns);
}

}  // extern "C"
