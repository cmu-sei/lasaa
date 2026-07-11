// Demo input for multiple rounds of `need_defs`.
//
// <legal>
// LASAA tool
//
// Copyright 2026 Carnegie Mellon University.
//
// NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
// INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
// UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
// TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
// OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
// MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
// WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
//
// Licensed under a MIT (SEI)-style license, please see License.txt or contact
// permission@sei.cmu.edu for full terms.
//
// [DISTRIBUTION STATEMENT A] This material has been approved for public
// release and unlimited distribution.  Please see Copyright notice for
// non-US Government use and distribution.
//
// This Software includes and/or makes use of Third-Party Software each subject
// to its own license.
//
// DM26-0426
// </legal>

#define DEMO_RECORD_CAPACITY 8
#define DEMO_SLOT_COUNT DEMO_RECORD_CAPACITY
#define DEMO_MAX_INDEX DEMO_SLOT_COUNT

struct demo_record {
    char payload[DEMO_SLOT_COUNT];
};

#define DEMO_INDEX_OK(index_) ((index_) >= 0 && (index_) <= DEMO_MAX_INDEX)
#define DEMO_WRITE_BYTE(record_, index_, value_) \
    ((record_)->payload[(index_)] = (value_))
#define DEMO_STORE(record_, index_, value_) \
    do { \
        if (DEMO_INDEX_OK(index_)) { \
            DEMO_WRITE_BYTE((record_), (index_), (value_)); \
        } \
    } while (0)

void demo_sink(const char *input, int index)
{
    struct demo_record rec = {0};

    DEMO_STORE(&rec, index, input[index]);
}
