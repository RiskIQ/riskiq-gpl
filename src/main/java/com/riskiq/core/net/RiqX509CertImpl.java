package com.riskiq.core.net;

/*
 * Copyright (c) 1996, 2020, Oracle and/or its affiliates. All rights reserved.
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

import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500Principal;

import sun.security.util.*;
import sun.security.provider.X509Factory;
import sun.security.x509.*;

/**
 * copied from sun.security.x509.X509CertImpl.
 *
 */
public class RiqX509CertImpl extends X509CertImpl implements DerEncoder {

    private static final long serialVersionUID = -3457612960190864406L;

    private static final String DOT = ".";


    // when we sign and decode we set this to true
    // this is our means to make certificates immutable
    private boolean readOnly = false;

    // Certificate data, and its envelope
    private byte[]              signedCert = null;
    protected RiqX509CertInfo info = null;
    protected AlgorithmId algId = null;
    protected byte[]            signature = null;

    /**
     * Default constructor.
     */
    public RiqX509CertImpl() { }

    /**
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes.  This form of constructor is used by agents which
     * need to examine and use certificate contents.  That is, this is
     * one of the more commonly used constructors.  Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end.  If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param certData the encoded bytes, with no trailing padding.
     * @exception CertificateException on parsing and initialization errors.
     */
    public RiqX509CertImpl(byte[] certData) throws CertificateException {
        try {
            parse(new DerValue(certData));
        } catch (IOException e) {
            signedCert = null;
            throw new CertificateException("Unable to initialize, " + e, e);
        }
    }

    /**
     * unmarshals an X.509 certificate from an input stream.  If the
     * certificate is RFC1421 hex-encoded, then it must begin with
     * the line X509Factory.BEGIN_CERT and end with the line
     * X509Factory.END_CERT.
     *
     * @param in an input stream holding at least one certificate that may
     *        be either DER-encoded or RFC1421 hex-encoded version of the
     *        DER-encoded certificate.
     * @exception CertificateException on parsing and initialization errors.
     */
    public RiqX509CertImpl(InputStream in) throws CertificateException {

        DerValue der = null;

        BufferedInputStream inBuffered = new BufferedInputStream(in);

        // First try reading stream as HEX-encoded DER-encoded bytes,
        // since not mistakable for raw DER
        try {
            inBuffered.mark(Integer.MAX_VALUE);
            der = readRFC1421Cert(inBuffered);
        } catch (IOException ioe) {
            try {
                // Next, try reading stream as raw DER-encoded bytes
                inBuffered.reset();
                der = new DerValue(inBuffered);
            } catch (IOException ioe1) {
                throw new CertificateException("Input stream must be " +
                        "either DER-encoded bytes " +
                        "or RFC1421 hex-encoded " +
                        "DER-encoded bytes: " +
                        ioe1.getMessage(), ioe1);
            }
        }
        try {
            parse(der);
        } catch (IOException ioe) {
            signedCert = null;
            throw new CertificateException("Unable to parse DER value of " +
                    "certificate, " + ioe, ioe);
        }
    }

    /**
     * read input stream as HEX-encoded DER-encoded bytes
     *
     * @param in InputStream to read
     * @returns DerValue corresponding to decoded HEX-encoded bytes
     * @throws IOException if stream can not be interpreted as RFC1421
     *                     encoded bytes
     */
    private DerValue readRFC1421Cert(InputStream in) throws IOException {
        DerValue der = null;
        String line = null;
        BufferedReader certBufferedReader =
                new BufferedReader(new InputStreamReader(in, "ASCII"));
        try {
            line = certBufferedReader.readLine();
        } catch (IOException ioe1) {
            throw new IOException("Unable to read InputStream: " +
                    ioe1.getMessage());
        }
        if (line.equals(X509Factory.BEGIN_CERT)) {
            /* stream appears to be hex-encoded bytes */
            ByteArrayOutputStream decstream = new ByteArrayOutputStream();
            try {
                while ((line = certBufferedReader.readLine()) != null) {
                    if (line.equals(X509Factory.END_CERT)) {
                        der = new DerValue(decstream.toByteArray());
                        break;
                    } else {
                        decstream.write(Pem.decode(line));
                    }
                }
            } catch (IOException ioe2) {
                throw new IOException("Unable to read InputStream: "
                        + ioe2.getMessage());
            }
        } else {
            throw new IOException("InputStream is not RFC1421 hex-encoded " +
                    "DER bytes");
        }
        return der;
    }

    /**
     * Construct an initialized X509 Certificate. The certificate is stored
     * in raw form and has to be signed to be useful.
     *
     * @params info the X509CertificateInfo which the Certificate is to be
     *              created from.
     */
    public RiqX509CertImpl(RiqX509CertInfo certInfo) {
        this.info = certInfo;
    }

    /**
     * Unmarshal a certificate from its encoded form, parsing a DER value.
     * This form of constructor is used by agents which need to examine
     * and use certificate contents.
     *
     * @param derVal the der value containing the encoded cert.
     * @exception CertificateException on parsing and initialization errors.
     */
    public RiqX509CertImpl(DerValue derVal) throws CertificateException {
        try {
            parse(derVal);
        } catch (IOException e) {
            signedCert = null;
            throw new CertificateException("Unable to initialize, " + e, e);
        }
    }

    /**
     * Set the requested attribute in the certificate.
     *
     * @param name the name of the attribute.
     * @param obj the value of the attribute.
     * @exception CertificateException on invalid attribute identifier.
     * @exception IOException on encoding error of attribute.
     */
    @Override
    public void set(String name, Object obj)
            throws CertificateException, IOException {
        // check if immutable
        if (readOnly) {
            throw new CertificateException("cannot over-write existing"
                    + " certificate");
        }

        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateException("Invalid root of attribute name,"
                    + " expected [" + NAME + "], received " + id);
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (attr.getSuffix() == null) {
                if (!(obj instanceof RiqX509CertInfo)) {
                    throw new CertificateException("Attribute value should"
                            + " be of type X509CertInfo.");
                }
                info = (RiqX509CertInfo)obj;
                signedCert = null;  //reset this as certificate data has changed
            } else {
                info.set(attr.getSuffix(), obj);
                signedCert = null;  //reset this as certificate data has changed
            }
        } else {
            throw new CertificateException("Attribute name not recognized or " +
                    "set() not allowed for the same: " + id);
        }
    }


    /**
     * Gets the subject distinguished name from the certificate.
     *
     * @return the subject name.
     */
    @Override
    public Principal getSubjectDN() {
        if (info == null)
            return null;
        try {
            Principal subject = (Principal)info.get(RiqX509CertInfo.SUBJECT + DOT +
                    RiqX509CertInfo.DN_NAME);
            return subject;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get subject name as X500Principal. Overrides implementation in
     * X509Certificate with a slightly more efficient version that is
     * also aware of X509CertImpl mutability.
     */
    @Override
    public X500Principal getSubjectX500Principal() {
        if (info == null) {
            return null;
        }
        try {
            X500Principal subject = (X500Principal)info.get(
                    RiqX509CertInfo.SUBJECT + DOT +
                            "x500principal");
            return subject;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the issuer distinguished name from the certificate.
     *
     * @return the issuer name.
     */
    @Override
    public Principal getIssuerDN() {
        if (info == null)
            return null;
        try {
            Principal issuer = (Principal)info.get(RiqX509CertInfo.ISSUER + DOT +
                    RiqX509CertInfo.DN_NAME);
            return issuer;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get issuer name as X500Principal. Overrides implementation in
     * X509Certificate with a slightly more efficient version that is
     * also aware of X509CertImpl mutability.
     */
    @Override
    public X500Principal getIssuerX500Principal() {
        if (info == null) {
            return null;
        }
        try {
            X500Principal issuer = (X500Principal)info.get(
                    RiqX509CertInfo.ISSUER + DOT +
                            "x500principal");
            return issuer;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the Issuer Unique Identity from the certificate.
     *
     * @return the Issuer Unique Identity.
     */
    @Override
    public boolean[] getIssuerUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity)info.get(
                    RiqX509CertInfo.ISSUER_ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the Subject Unique Identity from the certificate.
     *
     * @return the Subject Unique Identity.
     */
    @Override
    public boolean[] getSubjectUniqueID() {
        if (info == null)
            return null;
        try {
            UniqueIdentity id = (UniqueIdentity)info.get(
                    RiqX509CertInfo.SUBJECT_ID);
            if (id == null)
                return null;
            else
                return (id.getId());
        } catch (Exception e) {
            return null;
        }
    }

    /************************************************************/

    /*
     * Cert is a SIGNED ASN.1 macro, a three elment sequence:
     *
     *  - Data to be signed (ToBeSigned) -- the "raw" cert
     *  - Signature algorithm (SigAlgId)
     *  - The signature bits
     *
     * This routine unmarshals the certificate, saving the signature
     * parts away for later verification.
     */
    private void parse(DerValue val)
            throws CertificateException, IOException {
        // check if can over write the certificate
        if (readOnly) {
            throw new CertificateParsingException(
                    "cannot over-write existing certificate");
        }

        if (val.data == null || val.tag != DerValue.tag_Sequence)
            throw new CertificateParsingException(
                    "invalid DER-encoded certificate data");

        signedCert = val.toByteArray();
        DerValue[] seq = new DerValue[3];

        seq[0] = val.data.getDerValue();
        seq[1] = val.data.getDerValue();
        seq[2] = val.data.getDerValue();

        if (val.data.available() != 0) {
            throw new CertificateParsingException("signed overrun, bytes = "
                    + val.data.available());
        }
        if (seq[0].tag != DerValue.tag_Sequence) {
            throw new CertificateParsingException("signed fields invalid");
        }

        algId = AlgorithmId.parse(seq[1]);
        signature = seq[2].getBitString();

        if (seq[1].data.available() != 0) {
            throw new CertificateParsingException("algid field overrun");
        }
        if (seq[2].data.available() != 0)
            throw new CertificateParsingException("signed fields overrun");

        // The CertificateInfo
        info = new RiqX509CertInfo(seq[0]);

        // the "inner" and "outer" signature algorithms must match
        AlgorithmId infoSigAlg = (AlgorithmId)info.get(
                CertificateAlgorithmId.NAME
                        + DOT +
                        CertificateAlgorithmId.ALGORITHM);
        if (! algId.equals(infoSigAlg))
            throw new CertificateException("Signature algorithm mismatch");
        readOnly = true;
    }

    /**
     * Returned the encoding of the given certificate for internal use.
     * Callers must guarantee that they neither modify it nor expose it
     * to untrusted code. Uses getEncodedInternal() if the certificate
     * is instance of X509CertImpl, getEncoded() otherwise.
     */
    public static byte[] getEncodedInternal(Certificate cert)
            throws CertificateEncodingException {
        if (cert instanceof RiqX509CertImpl) {
            return ((RiqX509CertImpl)cert).getEncodedInternal();
        } else {
            return cert.getEncoded();
        }
    }

    /**
     * Utility method to convert an arbitrary instance of X509Certificate
     * to a X509CertImpl. Does a cast if possible, otherwise reparses
     * the encoding.
     */
    public static RiqX509CertImpl toImpl(X509Certificate cert)
            throws CertificateException {
        if (cert instanceof RiqX509CertImpl) {
            return (RiqX509CertImpl)cert;
        } else {
            return (RiqX509CertImpl)X509Factory.intern(cert);
        }
    }
}