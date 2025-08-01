import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@WebServlet("/upload")
@MultipartConfig(fileSizeThreshold = 1024 * 1024 * 2, // 2MB
                 maxFileSize = 1024 * 1024 * 10,      // 10MB
                 maxRequestSize = 1024 * 1024 * 50)   // 50MB
public class UploadServlet extends HttpServlet {

    private static final String UPLOAD_DIR = "uploaded_files"; // Directory where files will be saved

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // --- VULNERABLE CODE START ---

        // Get the absolute path to the directory where files will be stored
        // In a real application, this path should be outside the web root
        // and ideally in a secure, non-executable location.
        // For demonstration, we'll put it within the web application's context.
        String applicationPath = request.getServletContext().getRealPath("");
        String uploadFilePath = applicationPath + File.separator + UPLOAD_DIR;

        // Create the upload directory if it doesn't exist
        File uploadDir = new File(uploadFilePath);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }

        String fileName = null;
        try {
            for (Part part : request.getParts()) {
                fileName = getFileName(part);
                if (fileName != null && !fileName.isEmpty()) {
                    // Directly saving the file without any validation of content,
                    // file type (extension), or checking for malicious content.
                    // This is the core of the CWE-434 vulnerability.
                    try (InputStream input = part.getInputStream()) {
                        Files.copy(input, Paths.get(uploadFilePath + File.separator + fileName), StandardCopyOption.REPLACE_EXISTING);
                    }
                    request.setAttribute("message", "File " + fileName + " has uploaded successfully!");
                }
            }
        } catch (Exception ex) {
            request.setAttribute("message", "File Upload Failed due to " + ex.getMessage());
        }

        // --- VULNERABLE CODE END ---

        request.getRequestDispatcher("/index.jsp").forward(request, response);
    }

    /**
     * Utility method to get file name from HTTP header content-disposition
     */
    private String getFileName(Part part) {
        String contentDisp = part.getHeader("content-disposition");
        String[] tokens = contentDisp.split(";");
        for (String token : tokens) {
            if (token.trim().startsWith("filename")) {
                return token.substring(token.indexOf("=") + 2, token.length() - 1);
            }
        }
        return null;
    }
}
