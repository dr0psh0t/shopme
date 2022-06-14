package com.shopme.admin.service;

import com.shopme.admin.entity.User;
import com.shopme.admin.utils.Log;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.List;

public class UserCSVExporter {

    private List<User> users;

    public UserCSVExporter(List<User> users) {
        this.users = users;
    }

    public void exportToCsv(HttpServletResponse response) {

        response.setContentType("text/csv");
        response.addHeader("Content-Disposition", "attachment; filename=\"users.csv\"");

        try (Writer writer = response.getWriter();
                CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)) {
            csvPrinter.printRecord("ID", "E-mail", "Firstname", "Lastname", "Enabled", "Roles");

            for (User user : users) {
                csvPrinter.printRecord(user.getId(), user.getEmail(), user.getFirstName(),
                        user.getLastName(), user.getEnabled() == 1 ? "Yes" : "No", user.getRoles());
            }
        } catch (IOException e) {
            Log.error("Error While writing CSV: "+e);
        }
    }
}
