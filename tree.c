// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Forward declaration (implemented in object.c).
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

static int find_tree_entry(const Tree *tree, const char *name) {
    for (int i = 0; i < tree->count; i++) {
        if (strcmp(tree->entries[i].name, name) == 0) return i;
    }
    return -1;
}

static int load_index_for_tree(Index *index) {
    if (!index) return -1;
    index->count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') continue;
        if (index->count >= MAX_INDEX_ENTRIES) {
            fclose(f);
            return -1;
        }

        unsigned int mode;
        char hex[HASH_HEX_SIZE + 1];
        uint64_t mtime;
        unsigned int size;
        char path[512];

        int parsed = sscanf(line, "%o %64s %" SCNu64 " %u %511[^\r\n]",
                            &mode, hex, &mtime, &size, path);
        if (parsed != 5) {
            fclose(f);
            return -1;
        }

        IndexEntry *e = &index->entries[index->count++];
        memset(e, 0, sizeof(*e));
        e->mode = (uint32_t)mode;
        if (hex_to_hash(hex, &e->hash) != 0) {
            fclose(f);
            return -1;
        }
        e->mtime_sec = mtime;
        e->size = size;
        snprintf(e->path, sizeof(e->path), "%s", path);
    }

    if (ferror(f)) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

static int write_tree_level(const Index *index, const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;
    size_t prefix_len = strlen(prefix);

    for (int i = 0; i < index->count; i++) {
        const IndexEntry *entry = &index->entries[i];
        const char *rel = entry->path;

        if (prefix_len > 0) {
            if (strncmp(entry->path, prefix, prefix_len) != 0) continue;
            if (entry->path[prefix_len] != '/') continue;
            rel = entry->path + prefix_len + 1;
        }

        if (rel[0] == '\0') continue;

        const char *slash = strchr(rel, '/');
        if (!slash) {
            int existing = find_tree_entry(&tree, rel);
            if (existing >= 0) {
                if (tree.entries[existing].mode == MODE_DIR) return -1;
                tree.entries[existing].mode = entry->mode;
                tree.entries[existing].hash = entry->hash;
                continue;
            }

            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *out = &tree.entries[tree.count++];
            out->mode = entry->mode;
            out->hash = entry->hash;
            if (snprintf(out->name, sizeof(out->name), "%s", rel) >= (int)sizeof(out->name))
                return -1;
        } else {
            size_t dir_len = (size_t)(slash - rel);
            if (dir_len == 0 || dir_len >= sizeof(tree.entries[0].name)) return -1;

            char dir_name[256];
            memcpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            int existing = find_tree_entry(&tree, dir_name);
            if (existing >= 0) {
                if (tree.entries[existing].mode != MODE_DIR) return -1;
                continue;
            }

            char child_prefix[512];
            int n;
            if (prefix_len == 0) {
                n = snprintf(child_prefix, sizeof(child_prefix), "%s", dir_name);
            } else {
                n = snprintf(child_prefix, sizeof(child_prefix), "%s/%s", prefix, dir_name);
            }
            if (n < 0 || (size_t)n >= sizeof(child_prefix)) return -1;

            ObjectID child_id;
            if (write_tree_level(index, child_prefix, &child_id) != 0) return -1;

            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *out = &tree.entries[tree.count++];
            out->mode = MODE_DIR;
            out->hash = child_id;
            memcpy(out->name, dir_name, dir_len + 1);
        }
    }

    void *raw = NULL;
    size_t raw_len = 0;
    if (tree_serialize(&tree, &raw, &raw_len) != 0) return -1;

    int rc = object_write(OBJ_TREE, raw, raw_len, id_out);
    free(raw);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    if (!id_out) return -1;

    Index index;
    if (load_index_for_tree(&index) != 0) return -1;

    return write_tree_level(&index, "", id_out);
}
