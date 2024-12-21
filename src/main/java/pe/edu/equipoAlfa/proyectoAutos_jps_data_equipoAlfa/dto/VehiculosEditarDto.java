package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import java.util.Date;

public record VehiculosEditarDto(
        Integer idVehi,
        String nombre,
        String detalles,
        Boolean activo,
        Date fecha_lanzamiento,
        Integer stock,
        Double precio,
        Integer id_cat
) {
}
