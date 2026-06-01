/* Smoke C — vérifie que le header compile et que Smtp_Send/LastError
 * ont l'ABI attendue, sans envoyer de vrai mail (host invalide → false). */
#include "Amalgame_Net_Smtp.h"
#include <stdio.h>
int main(void) {
    GC_INIT();
    code_bool ok = Amalgame_Net_Smtp_Smtp_Send(
        "smtp.invalid.example", 465,
        "user", "pass",
        "from@example.com", "to@example.com",
        "Test", "Hello from Amalgame SMTP");
    printf("openssl_built: %d\n", AMALGAME_SMTP_HAVE_SSL);
    printf("send_failed_as_expected: %d\n", ok == 0 ? 1 : 0);
    printf("last_error: %s\n", Amalgame_Net_Smtp_Smtp_LastError());
    return 0;
}
