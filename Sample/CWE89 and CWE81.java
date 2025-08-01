package testcases;

import testcasesupport.*;
import javax.servlet.http.*;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.util.Properties;
import java.util.logging.Level;
import java.sql.*;

public class CWE81_CWE89_Merged extends AbstractTestCaseServlet {
    
    // CWE-81: XSS (Cross-Site Scripting) Methods
    private String badSource_XSS(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String data = ""; // Initialize data
        URLConnection urlConnection = (new URL("http://www.example.org/")).openConnection();
        try (BufferedReader readerBuffered = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), "UTF-8"))) {
            data = readerBuffered.readLine(); // POTENTIAL FLAW: Reading data from a URL
        } catch (IOException exceptIO) {
            IO.logger.log(Level.WARNING, "Error with stream reading", exceptIO);
        }
        return data;
    }

    private String goodSource_XSS(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        return "foo"; // FIX: Hardcoded string
    }

    public void bad_XSS(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String data = badSource_XSS(request, response);
        if (data != null) {
            response.sendError(404, "<br>bad() - Parameter name has value " + data); // POTENTIAL FLAW: XSS vulnerability
        }
    }

    public void good_XSS(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String data = goodSource_XSS(request, response);
        if (data != null) {
            response.sendError(404, "<br>good() - Parameter name has value " + data); // Safe usage
        }
    }

    // CWE-89: SQL Injection Methods
    private String badSource_SQL() throws Throwable {
        String data = ""; // Initialize data
        Properties properties = new Properties();
        try (FileInputStream streamFileInput = new FileInputStream("../common/config.properties")) {
            properties.load(streamFileInput);
            data = properties.getProperty("data"); // POTENTIAL FLAW: Reading data from a .properties file
        } catch (IOException exceptIO) {
            IO.logger.log(Level.WARNING, "Error with stream reading", exceptIO);
        }
        return data;
    }

    private String goodSource_SQL() throws Throwable {
        return "foo"; // FIX: Hardcoded string
    }

    public void bad_SQL() throws Throwable {
        String data = badSource_SQL();
        try (Connection dbConnection = IO.getDBConnection();
             Statement sqlStatement = dbConnection.createStatement()) {
            String query = "insert into users (status) values ('updated') where name='" + data + "'";
            sqlStatement.execute(query); // POTENTIAL FLAW: SQL Injection
        } catch (SQLException exceptSql) {
            IO.logger.log(Level.WARNING, "Database error", exceptSql);
        }
    }

    public void good_SQL_Prepared() throws Throwable {
        String data = badSource_SQL(); // Use bad source to demonstrate fix
        try (Connection dbConnection = IO.getDBConnection();
             PreparedStatement sqlStatement = dbConnection.prepareStatement(
                     "insert into users (status) values ('updated') where name=?")) {
            sqlStatement.setString(1, data); // FIX: Use prepared statement to prevent SQL Injection
            sqlStatement.execute();
        } catch (SQLException exceptSql) {
            IO.logger.log(Level.WARNING, "Database error", exceptSql);
        }
    }

    public void good_SQL_Hardcoded() throws Throwable {
        String data = goodSource_SQL(); // Use good source to demonstrate good practice
        try (Connection dbConnection = IO.getDBConnection();
             Statement sqlStatement = dbConnection.createStatement()) {
            String query = "insert into users (status) values ('updated') where name='" + data + "'";
            sqlStatement.execute(query); // Safe usage as data is hardcoded
        } catch (SQLException exceptSql) {
            IO.logger.log(Level.WARNING, "Database error", exceptSql);
        }
    }

    // Main method for testing purposes
    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        mainFromParent(args);
    }
}
