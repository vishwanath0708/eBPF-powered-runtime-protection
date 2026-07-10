package com.vanguard.target.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.file.Files;
import java.nio.file.Paths;

@Controller
public class ReportController {

    private static final String REPORTS_DIR = "/tmp/reports/";

    @GetMapping("/reports")
    public String reportsPage() {
        return "reports";
    }

    @PostMapping("/view-report")
    public String viewReport(@RequestParam String filename, Model model) {
        try {
            // VULNERABLE: Local File Inclusion (LFI)
            String filePath = REPORTS_DIR + filename;
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            
            model.addAttribute("filename", filename);
            model.addAttribute("content", content);
            model.addAttribute("success", true);

        } catch (Exception e) {
            model.addAttribute("error", "Could not read file: " + e.getMessage());
            model.addAttribute("success", false);
        }

        return "reports";
    }
}
