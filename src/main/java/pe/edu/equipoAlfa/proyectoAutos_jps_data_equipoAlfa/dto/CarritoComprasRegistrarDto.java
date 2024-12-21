package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

import java.math.BigDecimal;

public record CarritoComprasRegistrarDto(

        Integer idCarrito,          // ID del carrito
        Integer idVehiculo,         // ID del vehículo
        //String nombreVehiculo,      // Nombre del vehículo
        //Double precioVehiculo,  // Precio del vehículo
        Integer idUsuario,          // ID del cliente
        //String nombreCliente,       // Nombre del cliente
        //String correoCliente,       // Correo del cliente
        Integer cantidad,           // Cantidad comprada
        String direccionEntrega,    // Dirección de entrega
        Double montoTotal       // Monto total de la compra

) {
}
