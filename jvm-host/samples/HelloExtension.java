package sample;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
public class HelloExtension implements BurpExtension {
    public void initialize(MontoyaApi api) {
        api.extension().setName("Hello Shrike BApp");
        api.logging().logToOutput("Hello from a Java BApp running inside Shrike!");
        api.logging().logToOutput("Montoya services reachable: " + (api.http() != null));
    }
}
