package com.shopme.admin.service;

import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.shopme.admin.entity.User;
import com.shopme.admin.utils.Log;

import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.util.List;

public class UserPDFExporter {

    private List<User> listUsers;

    public UserPDFExporter(List<User> listUsers) {
        setListUsers(listUsers);
    }

    public void setListUsers(List<User> listUsers) {
        this.listUsers = listUsers;
    }

    private void writeTableHeader(PdfPTable table) {
        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(Color.orange);
        cell.setPadding(5);

        Font font = FontFactory.getFont(FontFactory.HELVETICA);
        font.setColor(java.awt.Color.WHITE);

        cell.setPhrase(new Phrase("User ID", font));

        table.addCell(cell);

        cell.setPhrase(new Phrase("E-mail", font));
        table.addCell(cell);

        cell.setPhrase(new Phrase("Full Name", font));
        table.addCell(cell);

        cell.setPhrase(new Phrase("Roles", font));
        table.addCell(cell);

        cell.setPhrase(new Phrase("Enabled", font));
        table.addCell(cell);
    }

    private void writeTableData(PdfPTable table, List<User> listUsers) {
        for (User user : listUsers) {
            table.addCell(String.valueOf(user.getId()));
            table.addCell(user.getEmail());
            table.addCell(user.getFirstName()+" "+user.getLastName());
            table.addCell(user.getRoles().toString());
            table.addCell(user.getEnabled() == 1 ? "Yes" : "No");
        }
    }

    public void exportToPdf(HttpServletResponse response) {
        try {
            response.setContentType("application/pdf");
            response.setHeader("Content-Disposition", "attachment; filename=users.pdf");

            Document document = new Document(PageSize.A4);
            PdfWriter.getInstance(document, response.getOutputStream());

            document.open();
            Font font = FontFactory.getFont(FontFactory.HELVETICA_BOLD);
            font.setSize(18);
            font.setColor(java.awt.Color.orange);

            Paragraph p = new Paragraph("List of Users", font);
            p.setAlignment(Paragraph.ALIGN_CENTER);

            document.add(p);

            PdfPTable table = new PdfPTable(5);
            table.setWidthPercentage(100f);
            table.setWidths(new float[] {1.5f, 3.5f, 3.0f, 3.0f, 1.5f});
            table.setSpacingBefore(10);

            writeTableHeader(table);
            writeTableData(table, listUsers);

            document.add(table);
            document.close();

        } catch (Exception e) {
            Log.error("Error While writing PDF: "+e);
        }
    }
}
