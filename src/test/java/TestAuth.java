import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.vitaxa.steamauth.AuthenticatorLinker;
import com.vitaxa.steamauth.Confirmation;
import com.vitaxa.steamauth.UserLogin;
import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class TestAuth {
    @Test
    public void testShit() {
        while(true) {
            System.out.println("Enter user/password: ");
            String username = readLine();
            String password = readLine();
            UserLogin login = new UserLogin(username, password);
            UserLogin.LoginResult response = UserLogin.LoginResult.BAD_CREDENTIALS;
            while ((response = login.doLogin()) != UserLogin.LoginResult.LOGIN_OKAY) {
                switch (response) {
                    case NEED_EMAIL:
                        System.out.println("Please enter your email code: ");
                        String code = readLine();
                        login.emailCode = code;
                        break;
                    case NEED_CAPTCHA:
                        System.out.println("Please enter captcha text: ");
                        String captchaText = readLine();
                        login.captchaText = captchaText;
                        break;
                    case NEED_2FA:
                        System.out.println("Please enter your mobile authenticator code: ");
                        code = readLine();
                        login.twoFactorCode = code;
                        break;
                }
            }
            AuthenticatorLinker linker = new AuthenticatorLinker(login.session);
            linker.setPhoneNumber(null); //Set this to non-null to add a new phone number to the account.
            AuthenticatorLinker.LinkResult result = linker.addAuthenticator();

            if (result != AuthenticatorLinker.LinkResult.AWAITING_FINALIZATION) {
                System.out.println("Failed to add authenticator: " + result);
                continue;
            }

            try {
                String sgFile = new Gson().toJson(linker.getLinkedAccount());
                String fileName = linker.getLinkedAccount().getAccountName() + ".maFile";
                OpenOption[] WRITE_OPTIONS = { StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING };
                Files.write(Paths.get(fileName), sgFile.getBytes(), WRITE_OPTIONS);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("EXCEPTION saving maFile. For security, authenticator will not be finalized.");
                continue;
            }

            System.out.println("Please enter SMS code: ");
            String smsCode = readLine();
            AuthenticatorLinker.FinalizeResult linkResult = linker.finalizeAddAuthenticator(smsCode);

            if (linkResult != AuthenticatorLinker.FinalizeResult.SUCCESS) {
                System.out.println("Unable to finalize authenticator: " + linkResult);
            }

        }
    }

    private static String readLine() {
        String s = "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
            s = br.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return s;
    }

}
