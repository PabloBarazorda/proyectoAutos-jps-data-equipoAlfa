package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasRegistrarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.VehiculosListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.VehiculosRegistrarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Clientes;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Vehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.VehiculoRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceCarritoService;

import java.util.List;

@Controller
@RequestMapping("/carrito")
public class CarritoComprasController {

    @Autowired
    MaintenanceCarritoService maintenanceCarritoService;


    @GetMapping("/listar")
    public String listarCarritoCompras(Model model) {
        List<CarritoComprasListarDto> carrito = maintenanceCarritoService.getAllCarritoCompras();
        model.addAttribute("carrito", carrito);
        return "carrito-comprasListar";
    }

    @GetMapping("/comprar")
    public String mostrarCompra(Model model) {

        List<Vehiculos> vehiculos = maintenanceCarritoService.getAllVehiculos();
        List<Clientes> clientes = maintenanceCarritoService.getAllClientes();

        model.addAttribute("carrito", new CarritoComprasRegistrarDto(null, 0, 0, 0, "", 0.0));
        model.addAttribute("vehiculos", vehiculos);
        model.addAttribute("clientes", clientes);

        return "carrito-comprasRegistrar";
    }

    // Procesar la compra
    @PostMapping("/comprar")
    public String realizarCompra(@ModelAttribute("carrito") CarritoComprasRegistrarDto carritoComprasRegistrarDto) {
        maintenanceCarritoService.realizarCompraCarrito(carritoComprasRegistrarDto);
        return "redirect:/carrito/listar";
    }


    @PostMapping("/delete/{id}")
    public String deleteCarritoById(@PathVariable int id) {
        try {
            maintenanceCarritoService.deleteCarritoCompraById(id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return "redirect:/carrito/listar";
    }





}
