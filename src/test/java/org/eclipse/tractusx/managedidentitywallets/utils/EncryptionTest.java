/*
 * *******************************************************************************
 *  Copyright (c) 2021,2023 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.managedidentitywallets.utils;

import org.eclipse.tractusx.managedidentitywallets.ManagedIdentityWalletsApplication;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.config.TestContextInitializer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = {ManagedIdentityWalletsApplication.class})
@ContextConfiguration(initializers = {TestContextInitializer.class})
class EncryptionTest {

    @Autowired
    private EncryptionUtils encryptionUtils;
    @Autowired
    private MIWSettings miwSettings;

    @Test
    void encryptionTest() {
        String originalMassage = "Dummy test message";
        String encrypt = encryptionUtils.encrypt(originalMassage);
        String decrypt = encryptionUtils.decrypt(encrypt);
        Assertions.assertEquals(originalMassage, decrypt);
    }

    @Test
    void givenPassword_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            InvalidAlgorithmParameterException, NoSuchPaddingException {

        String plainText = "-----BEGIN PRIVATE KEY-----\n" +
                "94CyfbZLcCZ/3b+zTqpzZTlocGvMTFYYc0hfSE+E7HY=\n" +
                "-----END PRIVATE KEY-----\n";
        String password = "tl57qilhklaqzi6aozfjg1k26oz3gxs6";
        miwSettings = new MIWSettings(null, password, null, null, null,
        null, null, null, null, false, null,
                null);
        encryptionUtils = new EncryptionUtils(miwSettings);
        String cipherText = encryptionUtils.encryptPasswordBased(plainText);
        String decryptedCipherText = encryptionUtils.decryptPasswordBased(cipherText);
        Assertions.assertEquals(plainText, decryptedCipherText);
    }

}
