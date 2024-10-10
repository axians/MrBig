#include "clientlog.h"
#include <wincrypt.h>

#define CERTIFICATES_ROW_SIZE (512)

typedef struct {
    CHAR *Subject;
    CHAR *FriendlyName;
    CHAR *Issuer;
    CHAR **EKUPurposes;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CHAR *StoreLocation;
} Certificate;

LPSTR certificates_PrettyEKUPurposes(CHAR **eku, LPSTR out, size_t outSize) {
    if (eku != NULL) {
        DWORD i = 0, written = 0;
        while (eku[i] != NULL) {
            if (i != 0 && outSize - written > 1) {
                out[written++] = ',';
            }
            written += snprintf(&out[written], outSize - written, "%s", eku[i++]);
        }
    } else {
        snprintf(out, outSize, "None");
    }
    return out;
}

LPSTR certificates_PrettyCertificate(Certificate *c, LPSTR out) {
    CHAR eku[64];
    snprintf(out, CERTIFICATES_ROW_SIZE, "\nFriendly Name:\t%s\nStore location:\t%s\nSubject:\t%s\nIssued by:\t%s\nIntended purposes: %s", c->FriendlyName, c->StoreLocation, c->Subject, c->Issuer, certificates_PrettyEKUPurposes(c->EKUPurposes, eku, sizeof(eku)));
    return out;
}

CHAR **certificates_GetEKUPurposes(CERT_INFO *ctx, clog_Arena *a) {
    CHAR **res = NULL;
    for (DWORD i = 0; i < ctx->cExtension; i++) {
        CERT_EXTENSION *ext = &ctx->rgExtension[i];
        if (strcmp(ext->pszObjId, szOID_ENHANCED_KEY_USAGE) != 0) continue;

        DWORD decodedSize = 0;
        CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE, ext->Value.pbData, ext->Value.cbData, CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &decodedSize);

        BYTE decodedData[decodedSize];
        WINBOOL success = CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE, ext->Value.pbData, ext->Value.cbData, CRYPT_DECODE_NOCOPY_FLAG, NULL, decodedData, &decodedSize);

        if (!success) {
            res = clog_ArenaAlloc(a, CHAR *, 2);
            res[0] = clog_ArenaAlloc(a, CHAR, 32);
            sprintf(res[0], "<Error with code %#010lx>", GetLastError());
            res[1] = NULL;
            break;
        }
        CTL_USAGE *p = ((CTL_USAGE *)decodedData);
        res = clog_ArenaAlloc(a, CHAR *, p->cUsageIdentifier + 1);
        for (DWORD j = 0; j < p->cUsageIdentifier; j++) {
            CHAR *oID = p->rgpszUsageIdentifier[j];
            const CRYPT_OID_INFO *oIDInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, oID, CRYPT_OID_DISABLE_SEARCH_DS_FLAG);

            CHAR purposeBuf[32];
            DWORD purposeLen = wcstombs(purposeBuf, oIDInfo->pwszName, 31);
            CHAR *purpose = clog_ArenaAlloc(a, CHAR, purposeLen + 1);
            memcpy(purpose, purposeBuf, purposeLen);
            purpose[purposeLen] = '\0';
            res[j] = purpose;
        }
        res[p->cUsageIdentifier] = NULL;
        break;
    }
    return res;
}

WINBOOL CertCloseStoreWrapper(HCERTSTORE h) {
    return CertCloseStore(h, 0);
}

void clog_certificates(clog_Arena scratch) {
    const LPSTR storeLocation = "MY";

    clog_ArenaAppend(&scratch, "[certificates]");

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, "My");
    clog_Defer(&scratch, hStore, RETURN_INT, &CertCloseStoreWrapper);

    // HCERTSTORE hStore = CertOpenSystemStoreA(0, storeLocation);
    // CertControlStore(hStore, 0, CERT_STORE_CTRL_AUTO_RESYNC, NULL);

    const CERT_CONTEXT *ctx = NULL;
    CHAR certificateBuf[CERTIFICATES_ROW_SIZE];
    DWORD numCertificates = 0;

    while ((ctx = CertEnumCertificatesInStore(hStore, ctx))) {
        clog_Defer(&scratch, (void *)ctx, RETURN_INT, &CertFreeCertificateContext);
        numCertificates++;
        Certificate c = {0};

        // Friendly Name
        DWORD friendlySize = 0;
        BOOL ok = CertGetCertificateContextProperty(ctx, CERT_FRIENDLY_NAME_PROP_ID, NULL, &friendlySize);
        if (ok) {
            BYTE friendlyNameUTF16[friendlySize];
            CertGetCertificateContextProperty(ctx, CERT_FRIENDLY_NAME_PROP_ID, friendlyNameUTF16, &friendlySize);
            CHAR friendlyNameUTF8[friendlySize];
            friendlySize = wcstombs(friendlyNameUTF8, (wchar_t *)friendlyNameUTF16, friendlySize - 1);
            c.FriendlyName = clog_ArenaAlloc(&scratch, void, friendlySize + 1);
            memcpy(c.FriendlyName, friendlyNameUTF8, friendlySize);
            c.FriendlyName[friendlySize] = '\0';
        } else {
            c.FriendlyName = "-";
        }

        // Subject
        DWORD getNameStringType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
        DWORD subjectSize = CertGetNameStringA(ctx, CERT_NAME_RDN_TYPE, CERT_NAME_DISABLE_IE4_UTF8_FLAG, &getNameStringType, NULL, 0);
        c.Subject = clog_ArenaAlloc(&scratch, void, subjectSize);
        CertGetNameString(ctx, CERT_NAME_RDN_TYPE, CERT_NAME_DISABLE_IE4_UTF8_FLAG, &getNameStringType, c.Subject, subjectSize);

        // Issued By
        getNameStringType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
        DWORD issuerSize = CertGetNameStringA(ctx, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG | CERT_NAME_DISABLE_IE4_UTF8_FLAG, &getNameStringType, NULL, 0);
        c.Issuer = clog_ArenaAlloc(&scratch, void, issuerSize);
        CertGetNameString(ctx, CERT_NAME_RDN_TYPE, CERT_NAME_DISABLE_IE4_UTF8_FLAG, &getNameStringType, c.Issuer, issuerSize);

        // Intended Purposes
        c.EKUPurposes = certificates_GetEKUPurposes(ctx->pCertInfo, &scratch);

        // rest
        c.NotBefore = ctx->pCertInfo->NotBefore;
        c.NotAfter = ctx->pCertInfo->NotAfter;
        c.StoreLocation = "Local Machine";

        clog_ArenaAppend(&scratch, "%s\n", certificates_PrettyCertificate(&c, certificateBuf));
        clog_IgnorePopDefer(&scratch);
    }
    if (numCertificates == 0) {
        clog_ArenaAppend(&scratch, "\n(No certificates found in store '%s')", storeLocation);
    }
}

#ifdef STANDALONE
int main(int argc, TCHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_certificates(st->Memory);
    printf("%s", st->Start);
    return 0;
}
#endif