package com.riskiq.core.net;

/*
 * Copyright 2004-2005 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */


/**
 * copied from sun.net.util.IPAddressUtil.
 *
 */
public class IPAddressUtil {
    private final static int INADDR4SZ = 4;
    private final static int INADDR16SZ = 16;
    private final static int INT16SZ = 2;

    /*
     * Converts IPv4 address in its textual presentation form
     * into its numeric binary form.
     *
     * Supports IPv4 shorthand where the the least significant bits are combined
     * into a single decimal value.  This processes differs from Network address shorthand
     *     192.168.1 == 192.168.0.1
     *     192.168.4097 == 192.168.16.1
     *
     * @param src a String representing an IPv4 address in standard format
     * @return a byte array representing the IPv4 numeric address
     */
    public static byte[] textToNumericFormatV4(String src) {
        if (src.length() == 0) {
            return null;
        }

        byte[] res = new byte[INADDR4SZ];
        String[] s = src.split("\\.", -1);
        long val;
        try {
            switch (s.length) {
                case 1:
                    /*
                     * When only one part is given, the value is stored directly in
                     * the network address without any byte rearrangement.
                     */

                    val = Long.parseLong(s[0]);
                    if (val < 0 || val > 0xffffffffL)
                        return null;
                    res[0] = (byte) ((val >> 24) & 0xff);
                    res[1] = (byte) (((val & 0xffffff) >> 16) & 0xff);
                    res[2] = (byte) (((val & 0xffff) >> 8) & 0xff);
                    res[3] = (byte) (val & 0xff);
                    break;
                case 2:
                    /*
                     * When a two part address is supplied, the last part is
                     * interpreted as a 24-bit quantity and placed in the right
                     * most three bytes of the network address. This makes the
                     * two part address format convenient for specifying Class A
                     * network addresses as net.host.
                     */

                    val = Integer.parseInt(s[0]);
                    if (val < 0 || val > 0xff)
                        return null;
                    res[0] = (byte) (val & 0xff);
                    val = Integer.parseInt(s[1]);
                    if (val < 0 || val > 0xffffff)
                        return null;
                    res[1] = (byte) ((val >> 16) & 0xff);
                    res[2] = (byte) (((val & 0xffff) >> 8) & 0xff);
                    res[3] = (byte) (val & 0xff);
                    break;
                case 3:
                    /*
                     * When a three part address is specified, the last part is
                     * interpreted as a 16-bit quantity and placed in the right
                     * most two bytes of the network address. This makes the
                     * three part address format convenient for specifying
                     * Class B net- work addresses as 128.net.host.
                     */
                    for (int i = 0; i < 2; i++) {
                        val = Integer.parseInt(s[i]);
                        if (val < 0 || val > 0xff)
                            return null;
                        res[i] = (byte) (val & 0xff);
                    }
                    val = Integer.parseInt(s[2]);
                    if (val < 0 || val > 0xffff)
                        return null;
                    res[2] = (byte) ((val >> 8) & 0xff);
                    res[3] = (byte) (val & 0xff);
                    break;
                case 4:
                    /*
                     * When four parts are specified, each is interpreted as a
                     * byte of data and assigned, from left to right, to the
                     * four bytes of an IPv4 address.
                     */
                    for (int i = 0; i < 4; i++) {
                        val = Integer.parseInt(s[i]);
                        if (val < 0 || val > 0xff)
                            return null;
                        res[i] = (byte) (val & 0xff);
                    }
                    break;
                default:
                    return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return res;
    }


    /**
     * @param src a String representing an IPv4 address in textual format
     * @return a boolean indicating whether src is an IPv4 literal address
     */
    public static boolean isIPv4LiteralAddress(String src) {
        return textToNumericFormatV4(src) != null;
    }
}
