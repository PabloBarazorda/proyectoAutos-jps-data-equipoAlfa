package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import lombok.Data;

import java.util.Date;

@Data
public class AdminDTO {
    private Integer id;
    private String nombreUsuario;
    private String correo;
    private Date fechaRegistro;
}
