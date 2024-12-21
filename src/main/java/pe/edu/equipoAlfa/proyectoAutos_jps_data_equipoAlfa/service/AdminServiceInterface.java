package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service;

import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Admin;

import java.util.List;

public interface AdminServiceInterface {
    List<Admin> getAllAdmins ();
    Admin getAdminById (Integer id);
    Admin saveAdmin(Admin admin);
    void deleteAdmin(Integer id);
}
