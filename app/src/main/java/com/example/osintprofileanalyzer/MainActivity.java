package com.example.osintprofileanalyzer;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import java.net.URI;
import java.util.*;
import java.util.regex.*;

public class MainActivity extends AppCompatActivity {
    EditText target, urls, publicText;
    TextView result;
    String lastReport = "";

    static final Map<String,String> PLATFORMS = new LinkedHashMap<String,String>() {{
        put("instagram.com","Instagram"); put("facebook.com","Facebook");
        put("x.com","X"); put("twitter.com","X/Twitter"); put("tiktok.com","TikTok");
        put("youtube.com","YouTube"); put("linkedin.com","LinkedIn");
        put("github.com","GitHub"); put("reddit.com","Reddit"); put("threads.net","Threads");
    }};

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        target=findViewById(R.id.target); urls=findViewById(R.id.urls);
        publicText=findViewById(R.id.publicText); result=findViewById(R.id.result);

        findViewById(R.id.analyze).setOnClickListener(v -> analyze());
        findViewById(R.id.export).setOnClickListener(v -> copyReport());
    }

    String usernameFromUrl(String raw) {
        try {
            String s = raw.trim();
            if (!s.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) s="https://"+s;
            URI u = URI.create(s);
            String path=u.getPath();
            if(path==null) return "";
            String[] parts=path.replaceAll("^/+|/+$","").split("/");
            if(parts.length==0) return "";
            String x=parts[0];
            if(x.matches("[A-Za-z0-9._-]{2,50}")) return x;
        } catch(Exception ignored){}
        return "";
    }

    String domain(String raw) {
        try {
            String s=raw.trim();
            if (!s.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) s="https://"+s;
            String h=URI.create(s).getHost();
            if(h==null) return "";
            return h.toLowerCase().replaceFirst("^www\\.","");
        } catch(Exception e){ return ""; }
    }

    void analyze() {
        String t=target.getText().toString().trim();
        String text=publicText.getText().toString();
        String[] lines=urls.getText().toString().split("\\R");

        LinkedHashSet<String> usernames=new LinkedHashSet<>();
        LinkedHashSet<String> emails=new LinkedHashSet<>();
        LinkedHashSet<String> phones=new LinkedHashSet<>();
        LinkedHashSet<String> domains=new LinkedHashSet<>();
        ArrayList<String> profiles=new ArrayList<>();

        Matcher um=Pattern.compile("(?<![\\w@])@([A-Za-z0-9._-]{2,30})").matcher(text);
        while(um.find()) usernames.add(um.group(1));

        Matcher em=Pattern.compile("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",Pattern.CASE_INSENSITIVE).matcher(text);
        while(em.find()) emails.add(em.group());

        Matcher pm=Pattern.compile("(?<!\\d)(?:\\+\\d{1,3}[\\s.-]?)?(?:\\(?\\d{2,4}\\)?[\\s.-]?)?\\d{3,4}[\\s.-]?\\d{3,4}(?!\\d)").matcher(text);
        while(pm.find()) if(pm.group().replaceAll("\\D","").length()>=7) phones.add(pm.group().trim());

        for(String raw: lines) {
            if(raw.trim().isEmpty()) continue;
            String d=domain(raw);
            if(d.isEmpty()) continue;
            domains.add(d);
            String platform="Unknown";
            for(String key:PLATFORMS.keySet()) {
                if(d.equals(key)||d.endsWith("."+key)){ platform=PLATFORMS.get(key); break; }
            }
            String u=usernameFromUrl(raw);
            if(!u.isEmpty()) usernames.add(u);
            profiles.add(platform+" | "+(u.isEmpty()?"[no username]":u)+" | "+raw.trim());
        }

        int score=Math.min(emails.size()*15,30)+Math.min(phones.size()*20,40)+Math.min(profiles.size()*5,25);
        String risk=score>=60?"HIGH PUBLIC EXPOSURE":score>=30?"MEDIUM PUBLIC EXPOSURE":"LOW PUBLIC EXPOSURE";

        StringBuilder r=new StringBuilder();
        r.append("PUBLIC PROFILE / OSINT REPORT\\n");
        r.append("==============================\\n");
        r.append("Target: ").append(t.isEmpty()?"[not supplied]":t).append("\\n");
        r.append("Assessment: ").append(risk).append("\\n\\n");
        r.append("USERNAMES\\n");
        for(String x:usernames) r.append(" • ").append(x).append("\\n");
        if(usernames.isEmpty()) r.append(" • None found\\n");

        r.append("\\nSOCIAL PROFILES\\n");
        for(String x:profiles) r.append(" • ").append(x).append("\\n");
        if(profiles.isEmpty()) r.append(" • None found\\n");

        r.append("\\nDOMAINS\\n");
        for(String x:domains) r.append(" • ").append(x).append("\\n");
        if(domains.isEmpty()) r.append(" • None found\\n");

        r.append("\\nPUBLIC EMAIL INDICATORS\\n");
        for(String x:emails) r.append(" • ").append(x).append("\\n");
        if(emails.isEmpty()) r.append(" • None found\\n");

        r.append("\\nPHONE CANDIDATES\\n");
        for(String x:phones) r.append(" • ").append(x).append("\\n");
        if(phones.isEmpty()) r.append(" • None found\\n");

        r.append("\\nNOTE\\n");
        r.append("Only information manually supplied to this app is analyzed.\\n");
        r.append("No login, private-account access, credential collection, or bypass is performed.\\n");

        lastReport=r.toString();
        result.setText(lastReport);
    }

    void copyReport() {
        if(lastReport.isEmpty()) {
            Toast.makeText(this,"Run an analysis first.",Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("OSINT Report",lastReport));
        Toast.makeText(this,"Report copied.",Toast.LENGTH_SHORT).show();
    }
}
