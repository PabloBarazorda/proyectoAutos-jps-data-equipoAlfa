package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import java.util.Date;

public record CarritoComprasListarDto(Integer idCarrito,
                                      String nombreCategoria,
                                      String nombreUsuario,
                                      Integer cantidad,
                                      String direccionEntrega,
                                      Double montoTotal,
                                      Date lastUpdate ) {
}
