#include "PCFG.h"
#include "md5.h"
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>

using namespace std;

static string to_hex_from_array(const array<bit32, 4>& h)
{
    stringstream ss;
    for (int i = 0; i < 4; i++)
    {
        ss << setw(8) << setfill('0') << hex << h[i];
    }
    return ss.str();
}

static string to_hex_from_raw(bit32 h[4])
{
    stringstream ss;
    for (int i = 0; i < 4; i++)
    {
        ss << setw(8) << setfill('0') << hex << h[i];
    }
    return ss.str();
}

int main()
{
    vector<string> tests = {
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111"
    };

    vector<array<bit32, 4>> simd_result;
    MD5HashBatchSIMD(tests, &simd_result);

    bool ok = true;

    for (size_t i = 0; i < tests.size(); i++)
    {
        bit32 serial_state[4];
        MD5Hash(tests[i], serial_state);

        string s1 = to_hex_from_raw(serial_state);
        string s2 = to_hex_from_array(simd_result[i]);

        cout << tests[i] << endl;
        cout << "serial: " << s1 << endl;
        cout << "simd:   " << s2 << endl;

        if (s1 != s2)
        {
            ok = false;
            cout << "mismatch" << endl;
        }

        cout << endl;
    }

    if (ok)
    {
        cout << "correctness passed" << endl;
    }
    else
    {
        cout << "correctness failed" << endl;
    }

    return ok ? 0 : 1;
}