package org.abstractj.kalium.version;
import static org.abstractj.kalium.NaCl.sodium;

public class Version
{
    String libsodiumVersion()
    {
        return sodium().sodium_version_string();
    }
}
