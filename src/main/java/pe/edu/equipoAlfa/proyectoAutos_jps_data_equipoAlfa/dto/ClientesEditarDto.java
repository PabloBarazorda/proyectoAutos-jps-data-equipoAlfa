package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import java.util.Date;

public record ClientesEditarDto(
        Integer idUsuario,
        String correo,
        String username,
        String nombre,
        String apellidos,
        String contrasenia,
        Integer telefono,
        String direccion,
        Date fechaRegistro ) {
}
