package com.shopme.admin.service;

import com.shopme.admin.entity.User;
import com.shopme.admin.utils.Log;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class UserExcelExporter {

    private List<User> users;

    public UserExcelExporter(List<User> users) {
        this.users = users;
    }

    public ByteArrayInputStream exportToExcel() {

        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("users");

            Row row = sheet.createRow(0);

            CellStyle headerCellStyle = workbook.createCellStyle();
            headerCellStyle.setFillForegroundColor(IndexedColors.LIGHT_GREEN.getIndex());
            headerCellStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

            Cell cell = row.createCell(0);
            cell.setCellValue("ID");
            cell.setCellStyle(headerCellStyle);

            cell = row.createCell(1);
            cell.setCellValue("E-mail");
            cell.setCellStyle(headerCellStyle);

            cell = row.createCell(2);
            cell.setCellValue("Firstname");
            cell.setCellStyle(headerCellStyle);

            cell = row.createCell(3);
            cell.setCellValue("Lastname");
            cell.setCellStyle(headerCellStyle);

            cell = row.createCell(4);
            cell.setCellValue("Enabled");
            cell.setCellStyle(headerCellStyle);

            cell = row.createCell(5);
            cell.setCellValue("Roles");
            cell.setCellStyle(headerCellStyle);

            for (int i = 0; i < users.size(); i++) {
                Row dataRow = sheet.createRow(i+1);

                dataRow.createCell(0).setCellValue(users.get(i).getId());
                dataRow.createCell(1).setCellValue(users.get(i).getEmail());
                dataRow.createCell(2).setCellValue(users.get(i).getFirstName());
                dataRow.createCell(3).setCellValue(users.get(i).getLastName());
                dataRow.createCell(4).setCellValue(users.get(i).getEnabled() == 1 ? "Yes" : "No");
                dataRow.createCell(5).setCellValue(users.get(i).getRoles().toString());
            }

            sheet.autoSizeColumn(0);
            sheet.autoSizeColumn(1);
            sheet.autoSizeColumn(2);
            sheet.autoSizeColumn(3);
            sheet.autoSizeColumn(4);
            sheet.autoSizeColumn(5);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            workbook.write(outputStream);

            return new ByteArrayInputStream(outputStream.toByteArray());
        } catch (IOException e) {
            Log.error("Error While writing Excel: "+e);
            return null;
        }
        // https://simplesolution.dev/spring-boot-download-excel-file-export-from-mysql/
    }
}
