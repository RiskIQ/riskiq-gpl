/*
 * Copyright (c) 1997, 2014, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.riskiq.core.net;

import java.io.IOException;
import java.io.OutputStream;

import java.security.cert.*;

import sun.security.util.*;
import sun.security.x509.*;


/**
 * copied from sun.security.x509.X509CertInfo.
 *
 */
public class RiqX509CertInfo extends X509CertInfo implements CertAttrSet<String> {



    // X509.v3 extensions
    protected CertificateExtensions     extensions = null;

    // DER encoded CertificateInfo data
    private byte[]      rawCertInfo = null;

    /**
     * Construct an uninitialized X509CertInfo on which <a href="#decode">
     * decode</a> must later be called (or which may be deserialized).
     */
    public RiqX509CertInfo() { }

    /**
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes.  This form of constructor is used by agents which
     * need to examine and use certificate contents.  That is, this is
     * one of the more commonly used constructors.  Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end.  If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param cert the encoded bytes, with no trailing data.
     * @exception CertificateParsingException on parsing errors.
     */
    public RiqX509CertInfo(byte[] cert) throws CertificateParsingException {
        try {
            DerValue    in = new DerValue(cert);

            parse(in);
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateParsingException on parsing errors.
     */
    public RiqX509CertInfo(DerValue derVal) throws CertificateParsingException {
        try {
            parse(derVal);
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }

    /**
     * Appends the certificate to an output stream.
     *
     * @param out an output stream to which the certificate is appended.
     * @exception CertificateException on encoding errors.
     * @exception IOException on other errors.
     */
    @Override
    public void encode(OutputStream out)
            throws CertificateException, IOException {
        if (rawCertInfo == null) {
            DerOutputStream tmp = new DerOutputStream();
            emit(tmp);
            rawCertInfo = tmp.toByteArray();
        }
        out.write(rawCertInfo.clone());
    }

    /**
     * Returns the encoded certificate info.
     *
     * @exception CertificateEncodingException on encoding information errors.
     */
    @Override
    public byte[] getEncodedInfo() throws CertificateEncodingException {
        try {
            if (rawCertInfo == null) {
                DerOutputStream tmp = new DerOutputStream();
                emit(tmp);
                rawCertInfo = tmp.toByteArray();
            }
            return rawCertInfo.clone();
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        } catch (CertificateException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    /**
     * Compares two X509CertInfo objects.  This is false if the
     * certificates are not both X.509 certs, otherwise it
     * compares them as binary data.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    @Override
    public boolean equals(Object other) {
        if (other instanceof RiqX509CertInfo) {
            return equals((RiqX509CertInfo) other);
        } else {
            return false;
        }
    }

    /**
     * Compares two certificates, returning false if any data
     * differs between the two.
     *
     * @param other the object being compared with this one
     * @return true iff the certificates are equivalent
     */
    public boolean equals(RiqX509CertInfo other) {
        if (this == other) {
            return(true);
        } else if (rawCertInfo == null || other.rawCertInfo == null) {
            return(false);
        } else if (rawCertInfo.length != other.rawCertInfo.length) {
            return(false);
        }
        for (int i = 0; i < rawCertInfo.length; i++) {
            if (rawCertInfo[i] != other.rawCertInfo[i]) {
                return(false);
            }
        }
        return(true);
    }

    /**
     * Calculates a hash code value for the object.  Objects
     * which are equal will also have the same hashcode.
     */
    @Override
    public int hashCode() {
        int     retval = 0;

        for (int i = 1; i < rawCertInfo.length; i++) {
            retval += rawCertInfo[i] * i;
        }
        return(retval);
    }

    /*
     * This routine unmarshals the certificate information.
     */
    private void parse(DerValue val)
            throws CertificateParsingException, IOException {
        DerInputStream  in;
        DerValue        tmp;

        if (val.tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }
        rawCertInfo = val.toByteArray();

        in = val.data;

        // Version
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte)0)) {
            version = new CertificateVersion(tmp);
            tmp = in.getDerValue();
        }

        // Serial number ... an integer
        serialNum = new CertificateSerialNumber(tmp);

        // Algorithm Identifier
        algId = new CertificateAlgorithmId(in);

        // Issuer name
        issuer = new X500Name(in);
//        if (issuer.isEmpty()) {
//            throw new CertificateParsingException(
//                    "Empty issuer DN not allowed in X509Certificates");
//        }

        // validity:  SEQUENCE { start date, end date }
        interval = new CertificateValidity(in);

        // subject name
        subject = new X500Name(in);
//        if ((version.compare(CertificateVersion.V1) == 0) &&
//                subject.isEmpty()) {
//            throw new CertificateParsingException(
//                    "Empty subject DN not allowed in v1 certificate");
//        }

        // public key
        pubKey = new CertificateX509Key(in);

        // If more data available, make sure version is not v1.
        if (in.available() != 0) {
            if (version.compare(CertificateVersion.V1) == 0) {
                throw new CertificateParsingException(
                        "no more data allowed for version 1 certificate");
            }
        } else {
            return;
        }

        // Get the issuerUniqueId if present
        tmp = in.getDerValue();
        if (tmp.isContextSpecific((byte)1)) {
            issuerUniqueId = new UniqueIdentity(tmp);
            if (in.available() == 0)
                return;
            tmp = in.getDerValue();
        }

        // Get the subjectUniqueId if present.
        if (tmp.isContextSpecific((byte)2)) {
            subjectUniqueId = new UniqueIdentity(tmp);
            if (in.available() == 0)
                return;
            tmp = in.getDerValue();
        }

        // Get the extensions.
        if (version.compare(CertificateVersion.V3) != 0) {
            throw new CertificateParsingException(
                    "Extensions not allowed in v2 certificate");
        }
        if (tmp.isConstructed() && tmp.isContextSpecific((byte)3)) {
            extensions = new CertificateExtensions(tmp.data);
        }

        // verify X.509 V3 Certificate
        verifyCert(subject, extensions);

    }

    /*
     * Verify if X.509 V3 Certificate is compliant with RFC 5280.
     */
    private void verifyCert(X500Name subject,
                            CertificateExtensions extensions)
            throws CertificateParsingException, IOException {

        // if SubjectName is empty, check for SubjectAlternativeNameExtension
        if (subject.isEmpty()) {
            if (extensions == null) {
//                throw new CertificateParsingException("X.509 Certificate is " +
//                        "incomplete: subject field is empty, and certificate " +
//                        "has no extensions");
                return;
            }
            SubjectAlternativeNameExtension subjectAltNameExt = null;
            SubjectAlternativeNameExtension extValue = null;
            GeneralNames names = null;
            try {
                subjectAltNameExt = (SubjectAlternativeNameExtension)
                        extensions.get(SubjectAlternativeNameExtension.NAME);
                names = subjectAltNameExt.get(
                        SubjectAlternativeNameExtension.SUBJECT_NAME);
            } catch (IOException e) {
//                throw new CertificateParsingException("X.509 Certificate is " +
//                        "incomplete: subject field is empty, and " +
//                        "SubjectAlternativeName extension is absent");
            }

            // SubjectAlternativeName extension is empty or not marked critical
//            if (names == null || names.isEmpty()) {
//                throw new CertificateParsingException("X.509 Certificate is " +
//                        "incomplete: subject field is empty, and " +
//                        "SubjectAlternativeName extension is empty");
//            } else if (subjectAltNameExt.isCritical() == false) {
//                throw new CertificateParsingException("X.509 Certificate is " +
//                        "incomplete: SubjectAlternativeName extension MUST " +
//                        "be marked critical when subject field is empty");
//            }
        }
    }

    /*
     * Marshal the contents of a "raw" certificate into a DER sequence.
     */
    private void emit(DerOutputStream out)
            throws CertificateException, IOException {
        DerOutputStream tmp = new DerOutputStream();

        // version number, iff not V1
        version.encode(tmp);

        // Encode serial number, issuer signing algorithm, issuer name
        // and validity
        serialNum.encode(tmp);
        algId.encode(tmp);

//        if ((version.compare(CertificateVersion.V1) == 0) &&
//                (issuer.toString() == null))
//            throw new CertificateParsingException(
//                    "Null issuer DN not allowed in v1 certificate");

        issuer.encode(tmp);
        interval.encode(tmp);

        // Encode subject (principal) and associated key
//        if ((version.compare(CertificateVersion.V1) == 0) &&
//                (subject.toString() == null))
//            throw new CertificateParsingException(
//                    "Null subject DN not allowed in v1 certificate");
        subject.encode(tmp);
        pubKey.encode(tmp);

        // Encode issuerUniqueId & subjectUniqueId.
        if (issuerUniqueId != null) {
            issuerUniqueId.encode(tmp, DerValue.createTag(DerValue.TAG_CONTEXT,
                    false,(byte)1));
        }
        if (subjectUniqueId != null) {
            subjectUniqueId.encode(tmp, DerValue.createTag(DerValue.TAG_CONTEXT,
                    false,(byte)2));
        }

        // Write all the extensions.
        if (extensions != null) {
            extensions.encode(tmp);
        }

        // Wrap the data; encoding of the "raw" cert is now complete.
        out.write(DerValue.tag_Sequence, tmp);
    }
}