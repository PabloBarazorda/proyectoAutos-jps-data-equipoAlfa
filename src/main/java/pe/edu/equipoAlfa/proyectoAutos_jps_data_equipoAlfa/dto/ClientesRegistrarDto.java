package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto;

public record ClientesRegistrarDto(
         Integer idUsuario,
         String correo,
         String username,
         String nombre,
         String apellidos,
         String contrasenia,
         Integer telefono,
         String direccion
) {
}
