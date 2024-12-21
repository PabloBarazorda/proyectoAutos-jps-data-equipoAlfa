package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import java.util.Date;

public record VehiculosListarDto(
        Integer idVehi,
        String nombre,
        String detalles,
        Boolean activo,
        Date fecha_lanzamiento,
        Integer stock,
        Double precio,
        String categoria,
        Date lastUpdate
) {
}
