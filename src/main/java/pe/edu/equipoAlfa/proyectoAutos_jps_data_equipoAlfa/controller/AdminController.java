package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.AdminDTO;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl.AdminService;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl.AdminService;

import java.util.List;

@Controller
@RequestMapping("/admins")
public class AdminController {
    @Autowired
    private AdminService adminService;

    @GetMapping
    public String getAllAdmins(Model model) {
        List<AdminDTO> admins = adminService.getAllAdminDTOs();
        model.addAttribute("admins", admins);
        return "AdminsListado";
    }

    @GetMapping("/new")
    public String createAdminForm(Model model) {
        model.addAttribute("admin", new AdminDTO());
        return "AdminCrear";
    }

    @PostMapping
    public String saveAdmin(@ModelAttribute AdminDTO adminDTO) {
        adminService.saveAdmin(adminService.convertToEntity(adminDTO));
        return "redirect:/admins";
    }

    @GetMapping("/edit/{id}")
    public String adminEditarDto(@PathVariable Integer id, Model model) {
        AdminDTO admin = adminService.getAdminDTOById(id);
        model.addAttribute("admin", admin);
        return "AdminCrear";
    }
}