package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.AdminDTO;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Admin;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.AdminRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.AdminServiceInterface;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AdminService implements AdminServiceInterface {
    @Autowired
    private AdminRepository adminRepository;

    @Override
    public List<Admin> getAllAdmins() {
        return adminRepository.findAll();
    }

    @Override
    public Admin getAdminById(Integer id) {
        return adminRepository.findById(id).orElse(null);
    }

    @Override
    public Admin saveAdmin(Admin admin) {
        return adminRepository.save(admin);
    }

    @Override
    public void deleteAdmin(Integer id) {
        adminRepository.deleteById(id);
    }

    // Métodos para trabajar con AdminDTO
    public List<AdminDTO> getAllAdminDTOs() {
        return adminRepository.findAll().stream().map(this::convertToDTO).collect(Collectors.toList());
    }

    public AdminDTO getAdminDTOById(Integer id) {
        Admin admin = adminRepository.findById(id).orElse(null);
        return admin != null ? convertToDTO(admin) : null;
    }

    public AdminDTO convertToDTO(Admin admin) {
        AdminDTO dto = new AdminDTO();
        dto.setId(admin.getId_admin());
        dto.setNombreUsuario(admin.getUsername());
        dto.setCorreo(admin.getCorreo());
        dto.setFechaRegistro(admin.getFecha_registro());
        return dto;
    }

    public Admin convertToEntity(AdminDTO dto) {
        Admin admin = new Admin();
        admin.setId_admin(dto.getId());
        admin.setUsername(dto.getNombreUsuario());
        admin.setCorreo(dto.getCorreo());
        admin.setFecha_registro(dto.getFechaRegistro());
        return admin;
    }
}
