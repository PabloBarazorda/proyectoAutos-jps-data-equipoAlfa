package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import lombok.Data;

import java.util.Date;

public record ClientesListarDto(
        Integer idUsuario,
        String nombre,
        String apellidos,
        String direccion,
        String correo,
        Integer telefono,
        Date fechaRegistro
                        ) {
}

