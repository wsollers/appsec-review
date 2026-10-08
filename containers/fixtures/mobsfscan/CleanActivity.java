package fixture;

class CleanActivity {
    void configure(android.webkit.WebView view) {
        view.getSettings().setJavaScriptEnabled(false);
    }
}
