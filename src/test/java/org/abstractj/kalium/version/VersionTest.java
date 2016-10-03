package org.abstractj.kalium.version;

import org.junit.Test;

public class VersionTest
{
    @Test
    public void testPrintVersionString()
    {
        Version v = new Version();
        System.out.println("libsodium version: " + v.libsodiumVersion());
    }
}
