package com.bolt12pay.companion;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private ServerSettings serverSettings;
    private String pendingTarget;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        serverSettings = new ServerSettings(this);
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        pendingTarget = extractLightningTarget(intent);
        boolean isPaymentIntent =
                Intent.ACTION_VIEW.equals(intent.getAction())
                        && intent.getData() != null
                        && isSupportedScheme(intent.getData().getScheme());

        if (isPaymentIntent && pendingTarget == null) {
            showMessageScreen(
                    getString(R.string.invalid_link_title),
                    getString(R.string.invalid_link_message));
            return;
        }

        String serverUrl = serverSettings.load();
        if (pendingTarget != null && serverUrl != null) {
            openPaymentForm(serverUrl, pendingTarget);
            return;
        }

        showSettingsScreen(serverUrl == null ? "" : serverUrl);
    }

    private String extractLightningTarget(Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        return data == null ? null : LightningTarget.normalize(data.toString());
    }

    private boolean isSupportedScheme(String scheme) {
        return "lightning".equalsIgnoreCase(scheme) || "bitcoin".equalsIgnoreCase(scheme);
    }

    private void showSettingsScreen(String currentServerUrl) {
        int padding = dp(24);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        content.setBackgroundColor(Color.rgb(11, 18, 32));

        content.addView(logo(), centered(dp(112), dp(112), 0, dp(18)));

        TextView title = text(getString(R.string.setup_title), 28, Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        content.addView(title);

        TextView explanation =
                text(getString(R.string.setup_explanation), 16, Color.rgb(200, 208, 224));
        explanation.setGravity(Gravity.CENTER);
        explanation.setLineSpacing(0, 1.12f);
        explanation.setPadding(0, dp(12), 0, dp(18));
        content.addView(explanation);

        if (pendingTarget != null) {
            TextView pending =
                    text(getString(R.string.pending_payment), 15, Color.rgb(247, 147, 26));
            pending.setPadding(0, 0, 0, dp(16));
            content.addView(pending);
        }

        EditText serverInput = new EditText(this);
        serverInput.setHint(R.string.server_url_hint);
        serverInput.setText(currentServerUrl);
        serverInput.setSingleLine(true);
        serverInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        serverInput.setTextColor(Color.WHITE);
        serverInput.setHintTextColor(Color.rgb(150, 160, 180));
        serverInput.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(247, 147, 26)));
        serverInput.setPadding(dp(12), 0, dp(12), 0);
        serverInput.setMinHeight(dp(52));
        content.addView(serverInput);

        TextView serverHelp =
                text(
                        getString(R.string.server_url_help),
                        13,
                        Color.rgb(170, 180, 198));
        serverHelp.setPadding(dp(12), dp(8), dp(12), 0);
        content.addView(serverHelp);

        Button saveButton = new Button(this);
        saveButton.setText(
                pendingTarget == null ? R.string.save_server : R.string.save_and_continue);
        saveButton.setTextColor(Color.rgb(11, 18, 32));
        saveButton.setTextSize(16);
        saveButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        saveButton.setMinHeight(dp(52));
        GradientDrawable buttonBackground = new GradientDrawable();
        buttonBackground.setColor(Color.rgb(247, 147, 26));
        buttonBackground.setCornerRadius(dp(14));
        saveButton.setBackground(buttonBackground);
        saveButton.setOnClickListener(
                ignored -> {
                    String normalized = ServerUrl.normalize(serverInput.getText().toString());
                    if (normalized == null) {
                        serverInput.setError(getString(R.string.server_url_error));
                        return;
                    }

                    if (!serverSettings.save(normalized)) {
                        serverInput.setError(getString(R.string.server_save_error));
                        return;
                    }
                    if (pendingTarget != null) {
                        openPaymentForm(normalized, pendingTarget);
                    } else {
                        Toast.makeText(this, R.string.server_saved, Toast.LENGTH_SHORT).show();
                        showSettingsScreen(normalized);
                    }
                });
        LinearLayout.LayoutParams buttonParams =
                new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT);
        buttonParams.topMargin = dp(16);
        content.addView(saveButton, buttonParams);

        TextView safety = text(getString(R.string.safety_note), 14, Color.rgb(170, 180, 198));
        safety.setPadding(0, dp(18), 0, 0);
        content.addView(safety);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
    }

    private void showMessageScreen(String titleText, String messageText) {
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(24), dp(24), dp(24));
        content.setBackgroundColor(Color.rgb(11, 18, 32));
        content.addView(logo(), centered(dp(112), dp(112), 0, dp(18)));
        TextView title = text(titleText, 28, Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        content.addView(title);

        TextView message = text(messageText, 16, Color.rgb(200, 208, 224));
        message.setPadding(0, dp(12), 0, 0);
        message.setGravity(Gravity.CENTER);
        message.setLineSpacing(0, 1.12f);
        content.addView(message);
        setContentView(content);
    }

    private void openPaymentForm(String serverUrl, String target) {
        String handoffUrl = ServerUrl.paymentHandoff(serverUrl, target);
        if (handoffUrl == null) {
            showMessageScreen(
                    getString(R.string.invalid_link_title),
                    getString(R.string.invalid_link_message));
            return;
        }

        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(handoffUrl));
        browserIntent.addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            startActivity(browserIntent);
            finish();
        } catch (ActivityNotFoundException error) {
            showMessageScreen(
                    getString(R.string.no_browser_title),
                    getString(R.string.no_browser_message));
        }
    }

    private TextView text(String value, int sizeSp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        return view;
    }

    private ImageView logo() {
        ImageView image = new ImageView(this);
        image.setImageResource(R.drawable.bolt12_pay_logo);
        image.setContentDescription(getString(R.string.app_name));
        image.setScaleType(ImageView.ScaleType.FIT_CENTER);
        return image;
    }

    private LinearLayout.LayoutParams centered(int width, int height, int top, int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(width, height);
        params.gravity = Gravity.CENTER_HORIZONTAL;
        params.topMargin = top;
        params.bottomMargin = bottom;
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
