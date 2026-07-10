/*
 * Copyright (C) 2021 
 * Authors: Ricardo Arguello
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.*
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package ec.gob.firmadigital.libreria.sign.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Properties;
import java.util.logging.Logger;

import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

import ec.gob.firmadigital.libreria.sign.RubricaSigner;
import ec.gob.firmadigital.libreria.sign.pdf.itext.SignerAdapter;
import java.util.logging.Level;

/**
 * PaDES Basic Signer
 */
public class PadesBasic extends BaseSigner {

    private final IExternalSignature externalSignature;

    private static final Logger LOGGER = Logger.getLogger(PadesBasic.class.getName());

    public PadesBasic(RubricaSigner signer) {
        this.externalSignature = new SignerAdapter(signer);
    }

    @Override
    protected byte[] signInternal(ByteArrayOutputStream os, com.itextpdf.signatures.PdfSigner pdfSigner, RubricaSigner signer,
            Certificate[] certChain, Properties params) throws IOException {
        try {
            pdfSigner.signDetached(new BouncyCastleDigest(), externalSignature, certChain, null, null, null, 0,
                    CryptoStandard.CMS);
            return os.toByteArray();
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error al firmar: {0}", e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
