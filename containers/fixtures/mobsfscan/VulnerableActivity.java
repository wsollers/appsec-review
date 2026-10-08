package fixture;

class VulnerableActivity {
    void configure(android.webkit.WebView view) {
        view.getSettings().setJavaScriptEnabled(true);
    }
}
